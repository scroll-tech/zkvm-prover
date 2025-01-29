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

mod blob;

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
        assert_eq!(digest, &proof.metadata.chunk_info.tx_data_digest);
    }

    let valid_chunk_size = chunk_proofs.len() as u16;
    let mut payload = meta_chunk_sizes
        .into_iter()
        .chain(std::iter::repeat(0))
        .take(max_chunks)
        .fold(
            Vec::from(valid_chunk_size.to_be_bytes()),
            |mut bytes, len| {
                bytes.extend_from_slice(&(len as u32).to_be_bytes());
                bytes
            },
        );

    let mut payload_for_challenge = Vec::from(keccak256(&payload).0);

    let data_hash = keccak256(
        chunk_proofs
            .iter()
            .map(|proof| &proof.metadata.chunk_info.data_hash)
            .fold(Vec::new(), |mut bytes, h| {
                bytes.extend_from_slice(&h.0);
                bytes
            }),
    );

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
    payload_for_challenge.extend_from_slice(blob_versioned_hash.as_slice());
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
    // println!("header host {:?}", batch_header);

    BatchProvingTask {
        chunk_proofs: Vec::from(chunk_proofs),
        batch_header,
        blob_bytes,
    }
}

#[test]
fn test_build_batch_task() -> eyre::Result<()> {
    use scroll_zkvm_prover::utils::{read_json, read_json_deep};

    // ./testdata/
    let path_testdata = std::path::Path::new("testdata");

    // read block witnesses.
    let paths_block_witnesses = [
        path_testdata.join("12508460.json"),
        path_testdata.join("12508461.json"),
        path_testdata.join("12508462.json"),
        path_testdata.join("12508463.json"),
    ];
    let read_block_witness = |path| Ok(read_json::<_, BlockWitness>(path)?);
    let chunk_task = ChunkProvingTask {
        block_witnesses: paths_block_witnesses
            .iter()
            .map(read_block_witness)
            .collect::<eyre::Result<Vec<BlockWitness>>>()?,
    };

    // read chunk proof.
    let path_chunk_proof = path_testdata
        .join("proofs")
        .join("chunk-12508460-12508463.json");
    let chunk_proof = read_json_deep::<_, ChunkProof>(&path_chunk_proof)?;

    build_batch_task(
        &[chunk_task],
        &[chunk_proof],
        scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
        Default::default(),
    );

    Ok(())
}
