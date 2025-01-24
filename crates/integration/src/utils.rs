mod blob;

use scroll_zkvm_prover::{
    ChunkProof,
    task::{batch::BatchProvingTask, chunk::ChunkProvingTask},
};
use scroll_zkvm_circuit_input_types::{batch::{BatchHeader, BatchHeaderV3}, utils::keccak256};
use sbv::primitives::{TransactionSigned, types::{BlockWitness, Transaction}};
use vm_zstd::zstd_encode;

fn is_l1_tx(tx: &Transaction) -> bool {
    // 0x7e is l1 tx
    tx.transaction_type == 0x7e
}

#[cfg(feature = "scroll")]
fn num_l1_txs(blk: &BlockWitness) -> u64 {
    // Get number of l1 txs. L1 txs can be skipped, so just counting is not enough
    blk
        .transaction
        .iter()
        .filter(|tx|is_l1_tx(tx))
        .map(|tx| tx.queue_index.expect("l1 msg should has queue index"))
        .max()
        .map(|end_l1_queue_index|end_l1_queue_index /*- blk.start_l1_queue_index*/ + 1)
        .unwrap_or_default()
}
#[cfg(not(feature = "scroll"))]
fn num_l1_txs(trace: &BlockWitness) -> u64 { 0 }

fn blks_tx_bytes<'a>(blks: impl Iterator<Item = &'a BlockWitness>) -> Vec<u8> {
    blks.flat_map(|blk|&blk.transaction)
        .filter(|tx| !is_l1_tx(tx))
        .fold(Vec::new(), |mut tx_bytes, tx|{
            TransactionSigned::try_from(tx)
                .unwrap()
                .encode_for_signing(&mut tx_bytes);
            tx_bytes
        })
}

pub fn build_batch_task(
    chunk_tasks: &[ChunkProvingTask],
    chunk_proofs: &[ChunkProof],
    max_chunks: usize,
    last_header: BatchHeaderV3,
) -> BatchProvingTask {
    // Sanity check.
    assert_eq!(chunk_tasks.len(), chunk_proofs.len());

    // collect required fields for batch header
    let l1_message_popped : u64 = chunk_tasks.iter()
        .flat_map(|t|&t.block_witnesses)
        .map(num_l1_txs)
        .sum();
    let last_block_timestamp = chunk_tasks.last().map_or(0u64, |t| {
        t.block_witnesses
            .last()
            .map_or(0, |trace| trace.header.timestamp)
    });


    // collect tx bytes from chunk tasks
    let (meta_chunk_sizes, chunk_tx_bytes) = chunk_tasks.iter()
        .fold((Vec::new(), Vec::new()), |(mut meta_chunk_sizes, mut payload_bytes), task|{
            let tx_bytes = blks_tx_bytes(task.block_witnesses.iter());
            meta_chunk_sizes.push(tx_bytes.len());
            payload_bytes.extend_from_slice(&tx_bytes);
            (meta_chunk_sizes, payload_bytes)
        });
 
    let mut payload = meta_chunk_sizes.iter()
        .fold(Vec::new(), |mut bytes, &len|{
            bytes.extend_from_slice(&(len as u16).to_be_bytes());
            bytes
        });

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

    // TODO: calc blob_data_proof ...
    // let point_evaluations = blob::point_evaluation(&coefficients, )

    let batch_header = BatchHeaderV3 {
        version: last_header.version,
        batch_index: last_header.batch_index + 1,
        l1_message_popped,
        last_block_timestamp,
        total_l1_message_popped: last_header.total_l1_message_popped + l1_message_popped,
        parent_batch_hash: last_header.batch_hash(),
        data_hash,
        blob_versioned_hash,
        blob_data_proof: Default::default(),
    };
    
    
    BatchProvingTask {
        chunk_proofs: Vec::from(chunk_proofs),
        batch_header,
        blob_bytes,
    }
}
