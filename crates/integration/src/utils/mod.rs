use sbv::primitives::{
    B256, U256,
    eips::Encodable2718,
    types::{BlockWitness, Transaction, reth::TransactionSigned},
};
use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeader, BatchHeaderV7},
    utils::keccak256,
};
use scroll_zkvm_prover::{
    ChunkProof,
    task::{batch::BatchProvingTask, chunk::ChunkProvingTask},
    utils::point_eval,
};
use vm_zstd::zstd_encode;

fn is_l1_tx(tx: &Transaction) -> bool {
    // 0x7e is l1 tx
    tx.transaction_type == 0x7e
}

#[allow(dead_code)]
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
        .filter(|tx| !is_l1_tx(tx))
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
            version: 7,
            batch_hash: B256::new([
                0xab, 0xac, 0xad, 0xae, 0xaf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
        }
    }
}

impl From<&BatchHeaderV7> for LastHeader {
    fn from(h: &BatchHeaderV7) -> Self {
        Self {
            batch_index: h.batch_index,
            version: h.version,
            batch_hash: h.batch_hash(),
        }
    }
}

pub fn build_batch_task(
    chunk_tasks: &[ChunkProvingTask],
    chunk_proofs: &[ChunkProof],
    last_header: LastHeader,
) -> BatchProvingTask {
    // Sanity check.
    assert_eq!(chunk_tasks.len(), chunk_proofs.len());

    let num_blocks = chunk_tasks
        .iter()
        .map(|t| t.block_witnesses.len())
        .sum::<usize>() as u16;

    let (prev_msg_queue_hash, initial_block_number) = {
        let first_chunk = &chunk_proofs
            .first()
            .expect("at least one chunk")
            .metadata
            .chunk_info;
        (
            first_chunk.prev_msg_queue_hash,
            first_chunk.initial_block_number,
        )
    };

    let post_msg_queue_hash = chunk_proofs
        .last()
        .expect("at least one chunk")
        .metadata
        .chunk_info
        .post_msg_queue_hash;

    // collect tx bytes from chunk tasks
    let (_, chunk_digests, chunk_tx_bytes) = chunk_tasks.iter().fold(
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
        assert_eq!(digest, &proof.metadata.chunk_info.tx_data_digest);
    }

    // collect all data together for payload
    let mut payload = Vec::new();
    payload.extend_from_slice(prev_msg_queue_hash.as_slice());
    payload.extend_from_slice(post_msg_queue_hash.as_slice());
    payload.extend(initial_block_number.to_be_bytes());
    payload.extend(num_blocks.to_be_bytes());
    assert_eq!(payload.len(), 74);
    let mut payload = chunk_proofs
        .iter()
        .flat_map(|proof| &proof.metadata.chunk_info.block_ctxs)
        .fold(payload, |mut pl, ctx| {
            pl.extend(ctx.to_bytes());
            pl
        });
    assert_eq!(payload.len(), 74 + 52 * num_blocks as usize);
    payload.extend(chunk_tx_bytes);
    // compress ...
    let compressed_payload = zstd_encode(&payload);

    let version = 7u32;
    let heading = compressed_payload.len() as u32 + (version << 24);

    let mut blob_bytes = Vec::from(heading.to_be_bytes());
    blob_bytes.push(1u8); // compressed flag
    blob_bytes.extend(compressed_payload);
    blob_bytes.resize(4096 * 31, 0);

    let kzg_blob = point_eval::to_blob(&blob_bytes);
    let kzg_commitment = point_eval::blob_to_kzg_commitment(&kzg_blob);
    let blob_versioned_hash = point_eval::get_versioned_hash(&kzg_commitment);

    // primage = keccak(payload) + blob_versioned_hash
    let mut chg_preimage = keccak256(&blob_bytes).to_vec();
    chg_preimage.extend(blob_versioned_hash.0);
    let challenge_digest = keccak256(&chg_preimage);

    let (kzg_proof, _) = point_eval::get_kzg_proof(&kzg_blob, challenge_digest);

    let batch_header = BatchHeaderV7 {
        version: last_header.version,
        batch_index: last_header.batch_index + 1,
        parent_batch_hash: last_header.batch_hash,
        blob_versioned_hash,
    };

    BatchProvingTask {
        chunk_proofs: Vec::from(chunk_proofs),
        batch_header,
        blob_bytes,
        challenge_digest: U256::from_be_bytes(challenge_digest.0),
        kzg_commitment: kzg_commitment.to_bytes(),
        kzg_proof: kzg_proof.to_bytes(),
    }
}

#[test]
fn test_build_and_parse_batch_task() -> eyre::Result<()> {
    use scroll_zkvm_circuit_input_types::batch::{EnvelopeV7, PayloadV7};
    use scroll_zkvm_prover::utils::{read_json, read_json_deep};

    // ./testdata/
    let path_testdata = std::path::Path::new("testdata");

    // read block witnesses.
    let paths_block_witnesses = [
        path_testdata.join("1.json"),
        path_testdata.join("2.json"),
        path_testdata.join("3.json"),
        path_testdata.join("4.json"),
    ];
    let read_block_witness = |path| Ok(read_json::<_, BlockWitness>(path)?);
    let chunk_task = ChunkProvingTask {
        block_witnesses: paths_block_witnesses
            .iter()
            .map(read_block_witness)
            .collect::<eyre::Result<Vec<BlockWitness>>>()?,
        prev_msg_queue_hash: Default::default(),
    };

    // read chunk proof.
    let path_chunk_proof = path_testdata.join("proofs").join("chunk-1-4.json");
    let chunk_proof = read_json_deep::<_, ChunkProof>(&path_chunk_proof)?;

    let task = build_batch_task(&[chunk_task], &[chunk_proof], Default::default());

    let enveloped = EnvelopeV7::from(task.blob_bytes.as_slice());

    let chunk_infos = task
        .chunk_proofs
        .iter()
        .map(|proof| proof.metadata.chunk_info.clone())
        .collect::<Vec<_>>();

    PayloadV7::from(&enveloped).validate(&task.batch_header, &chunk_infos);
    Ok(())
}
