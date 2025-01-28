mod blob;

use sbv::primitives::{
    B256, TransactionSigned, U256,
    eips::Encodable2718,
    types::{BlockWitness, Transaction},
};
use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeader, BatchHeaderV3},
    utils::keccak256,
};
use scroll_zkvm_prover::{
    ChunkProof,
    task::{batch::BatchProvingTask, chunk::ChunkProvingTask},
};
use vm_zstd::zstd_encode;

fn is_l1_tx(tx: &Transaction) -> bool {
    // 0x7e is l1 tx
    tx.transaction_type == 0x7e
}

#[cfg(feature = "scroll")]
fn final_l1_index(blk: &BlockWitness) -> u64 {
    // Get number of l1 txs. L1 txs can be skipped, so just counting is not enough
    // (The comment copied from scroll-prover, but why the max l1 queue index is always
    // the last one for a chunk, or, is the last l1 never being skipped?)
    blk.transaction
        .iter()
        .filter(|tx| is_l1_tx(tx))
        .map(|tx| tx.queue_index.expect("l1 msg should has queue index"))
        .max()
        .unwrap_or_default()
}
#[cfg(not(feature = "scroll"))]
fn num_l1_txs(trace: &BlockWitness) -> u64 {
    0
}

fn blks_tx_bytes<'a>(blks: impl Iterator<Item = &'a BlockWitness>) -> Vec<u8> {
    blks.flat_map(|blk| &blk.transaction)
        .filter(|tx| !is_l1_tx(tx)) // TODO: should we filter out l1 tx?
        .fold(Vec::new(), |mut tx_bytes, tx| {
            TransactionSigned::try_from(tx)
                .unwrap()
                .encode_2718(&mut tx_bytes);
            tx_bytes
        })
}

#[derive(Debug)]
pub struct LastHeader {
    pub batch_index: u64,
    pub l1_message_index: u64,
    pub batch_hash: B256,
    pub version: u8,
}

impl Default for LastHeader {
    fn default() -> Self {
        // create a default LastHeader according to the dummy value
        // being set in the e2e test in scroll-prover:
        // https://github.com/scroll-tech/scroll-prover/blob/82f8ed3fabee5c3001b0b900cda1608413e621f8/integration/tests/e2e_tests.rs#L203C1-L207C8

        Self {
            batch_index: 123,
            version: 4,
            batch_hash: B256::new([
                0xab, 0xac, 0xad, 0xae, 0xaf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            l1_message_index: 0,
        }
    }
}

impl From<&BatchHeaderV3> for LastHeader {
    fn from(h: &BatchHeaderV3) -> Self {
        Self {
            batch_index: h.batch_index + 1,
            version: h.version,
            batch_hash: h.batch_hash(),
            l1_message_index: h.total_l1_message_popped,
        }
    }
}

pub fn build_batch_task(
    chunk_tasks: &[ChunkProvingTask],
    chunk_proofs: &[ChunkProof],
    max_chunks: usize,
    last_header: LastHeader,
) -> BatchProvingTask {
    // Sanity check.
    assert_eq!(chunk_tasks.len(), chunk_proofs.len());

    // collect required fields for batch header
    let last_l1_message_index: u64 = chunk_tasks
        .iter()
        .flat_map(|t| &t.block_witnesses)
        .map(final_l1_index)
        .reduce(|last, cur| if cur == 0 { last } else { cur })
        .expect("at least one chunk");
    let last_l1_message_index = if last_l1_message_index == 0 {
        last_header.l1_message_index
    } else {
        last_l1_message_index
    };

    let last_block_timestamp = chunk_tasks.last().map_or(0u64, |t| {
        t.block_witnesses
            .last()
            .map_or(0, |trace| trace.header.timestamp)
    });

    // collect tx bytes from chunk tasks
    let (meta_chunk_sizes, chunk_digests, chunk_tx_bytes) = chunk_tasks.iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut meta_chunk_sizes, mut chunk_digests, mut payload_bytes), task| {
            let tx_bytes = blks_tx_bytes(task.block_witnesses.iter());
            meta_chunk_sizes.push(tx_bytes.len());
            chunk_digests.push(keccak256(&tx_bytes));
            payload_bytes.extend(tx_bytes);
            (meta_chunk_sizes, chunk_digests, payload_bytes)
        },
    );

    // sanity check
    for (digest, proof) in chunk_digests.iter().zip(chunk_proofs.iter()) {
        println!("{:x?}", proof.metadata.chunk_info);
        let chunk_pi = proof.metadata.chunk_info.public_input_hash(digest);
        println!("{:x?}, {:x?}", chunk_pi, proof.proof.public_values);
    }

    let mut payload = meta_chunk_sizes
        .into_iter()
        .chain(std::iter::repeat(0))
        .take(max_chunks)
        .fold(Vec::new(), |mut bytes, len| {
            bytes.extend_from_slice(&(len as u16).to_be_bytes());
            bytes
        });

    let mut payload_for_challenge = payload.clone();

    let data_hash = keccak256(&chunk_tx_bytes);
    // payload can setup
    payload.extend(chunk_tx_bytes);

    // compress ...
    let compressed_payload = zstd_encode(&payload);
    let mut blob_bytes = vec![1];
    blob_bytes.extend(compressed_payload);

    // generate versioned hash
    let coefficients = blob::get_coefficients(&blob_bytes);
    let blob_versioned_hash = blob::get_versioned_hash(&coefficients);

    // calc blob_data_proof ...
    let last_digest = chunk_digests.last().expect("at least we have one");

    payload_for_challenge.extend(
        chunk_digests
            .iter()
            .chain(std::iter::repeat(last_digest))
            .take(max_chunks)
            .fold(Vec::new(), |mut ret, digest| {
                ret.extend_from_slice(&digest.0);
                ret
            }),
    );
    let point_evaluations = blob::point_evaluation(
        &coefficients,
        U256::from_be_bytes(keccak256(payload_for_challenge).0),
    );

    let point_evaluations = [point_evaluations.0, point_evaluations.1];

    let batch_header = BatchHeaderV3 {
        version: last_header.version,
        batch_index: last_header.batch_index + 1,
        l1_message_popped: last_l1_message_index - last_header.l1_message_index,
        last_block_timestamp,
        total_l1_message_popped: last_l1_message_index,
        parent_batch_hash: last_header.batch_hash,
        data_hash,
        blob_versioned_hash,
        blob_data_proof: point_evaluations.map(|u| B256::new(u.to_be_bytes())),
    };

    BatchProvingTask {
        chunk_proofs: Vec::from(chunk_proofs),
        batch_header,
        blob_bytes,
    }
}

#[test]
fn test_build_batch_task() -> Result<(), scroll_zkvm_prover::Error> {
    use scroll_zkvm_prover::utils::{read_json, read_json_deep};
    use std::str::FromStr;

    let blk_name = [
        "12508460.json",
        "12508461.json",
        "12508462.json",
        "12508463.json",
    ];

    let chunk_proof_name = ["chunk-12508460-12508463.json"];

    let blk_witness = |n| read_json::<_, BlockWitness>(format!("testdata/{}", n)).unwrap();

    let mut chk_proof = chunk_proof_name
        .map(|n| read_json_deep::<_, ChunkProof>(format!("testdata/chunk/{}", n)).unwrap());

    chk_proof[0].metadata.chunk_info.withdraw_root = Some(
        B256::from_str("0x07ed4c7d56e2ed40f65d25eecbb0110f3b3f4db68e87700287c7e0cedcb68272")
            .unwrap(),
    );
    // manual match to chunk tasks
    let chk_task = [ChunkProvingTask {
        block_witnesses: Vec::from(blk_name.map(blk_witness)),
    }];

    build_batch_task(&chk_task, &chk_proof, 45, Default::default());

    Ok(())
}
