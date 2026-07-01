use std::path::{Path, PathBuf};

use eyre::Context;
use sbv_core::witness::BlockWitness;
use sbv_primitives::B256;
use scroll_zkvm_types_base::aggregation::{AggregationInput, ProgramCommitment};
use scroll_zkvm_types_base::public_inputs::{MultiVersionPublicInputs, Version};
use scroll_zkvm_types_base::public_inputs::scroll::{
    batch::BatchInfo,
    chunk::ChunkInfo,
};
use scroll_zkvm_types_batch::{BatchHeader as _, BatchHeaderV7, ReferenceHeader};
use scroll_zkvm_types_base::utils::keccak256;
use scroll_zkvm_types_batch::{
    BatchWitness, Envelope, EnvelopeV7, N_BLOB_BYTES, Payload, PayloadV7,
};
use scroll_zkvm_types_bundle::BundleWitness;
use scroll_zkvm_types_chunk::scroll::ChunkWitness;

const PATH_TESTDATA: &str = "../crates/integration/testdata";

/// Default fork/version used by the OpenVM integration tests.
pub fn testing_version() -> Version {
    Version::galileo_v2()
}

/// Read a block witness JSON file from the shared testdata.
pub fn read_block_witness<P>(path: P) -> eyre::Result<BlockWitness>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    if !path.exists() {
        eyre::bail!("block witness file not found: {}", path.display());
    }

    if let Ok(ret) = serde_json::from_reader::<_, BlockWitness>(std::fs::File::open(path)?) {
        Ok(ret)
    } else {
        let witness = std::fs::File::open(path)?;
        Ok(BlockWitness::from(serde_json::from_reader::<
            _,
            sbv_primitives::legacy_types::BlockWitness,
        >(witness)?))
    }
}

/// Build a `ChunkWitness` from a contiguous block range using shared testdata.
pub fn build_chunk_witness(block_range: impl Iterator<Item = u64>) -> eyre::Result<ChunkWitness> {
    let version = testing_version();
    let fork_dir = version.fork.to_string();
    let paths: Vec<PathBuf> = block_range
        .map(|block_n| {
            Path::new(PATH_TESTDATA)
                .join(&fork_dir)
                .join("witnesses")
                .join(format!("{}.json", block_n))
        })
        .collect();

    let block_witnesses: Vec<BlockWitness> = paths
        .iter()
        .map(read_block_witness)
        .collect::<eyre::Result<Vec<_>>>()
        .context("failed to read block witnesses")?;

    Ok(ChunkWitness::new_scroll(
        version.as_version_byte(),
        &block_witnesses,
        B256::repeat_byte(1u8),
        version.fork,
    ))
}

/// Default single-chunk block range matching OpenVM `preset_chunk`.
pub fn preset_chunk_block_range() -> Vec<u64> {
    (20239240u64..=20239245).collect()
}

/// Default block ranges for a small multi-chunk batch (GalileoV2).
pub fn preset_batch_chunk_ranges() -> Vec<Vec<u64>> {
    vec![vec![20239240, 20239241], vec![20239242, 20239243]]
}

/// Build a minimal GalileoV2 [`BatchWitness`] from a set of already-built chunk witnesses.
pub fn build_batch_witness(chunk_witnesses: &[ChunkWitness]) -> eyre::Result<BatchWitness> {
    let version = testing_version();

    let chunk_infos: Vec<ChunkInfo> = chunk_witnesses
        .iter()
        .cloned()
        .map(|w| ChunkInfo::try_from(w).map_err(|e| eyre::eyre!("chunk execution failed: {e}")))
        .collect::<eyre::Result<Vec<_>>>()?;

    // Collect L2 tx bytes per chunk and chunk digests.
    let (_meta_chunk_sizes, chunk_digests, chunk_tx_bytes): (Vec<usize>, Vec<B256>, Vec<u8>) =
        chunk_witnesses.iter().fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut sizes, mut digests, mut tx_bytes), chunk_wit| {
                let bytes: Vec<u8> = chunk_wit
                    .blocks
                    .iter()
                    .flat_map(|blk| &blk.transactions)
                    .filter(|tx| !tx.is_l1_message())
                    .fold(Vec::new(), |mut out, tx| {
                        use sbv_primitives::types::eips::Encodable2718;
                        tx.encode_2718(&mut out);
                        out
                    });
                sizes.push(bytes.len());
                digests.push(keccak256(&bytes));
                tx_bytes.extend(bytes);
                (sizes, digests, tx_bytes)
            },
        );

    for (digest, info) in chunk_digests.iter().zip(chunk_infos.iter()) {
        assert_eq!(digest, &info.tx_data_digest, "chunk tx digest mismatch");
    }

    let num_blocks = chunk_witnesses.iter().map(|w| w.blocks.len()).sum::<usize>() as u16;
    let prev_msg_queue_hash = chunk_witnesses[0].prev_msg_queue_hash;
    let initial_block_number = chunk_witnesses[0].blocks[0].header.number;
    let post_msg_queue_hash = chunk_infos
        .last()
        .expect("at least one chunk")
        .post_msg_queue_hash;

    let mut payload = Vec::new();
    payload.extend_from_slice(prev_msg_queue_hash.as_slice());
    payload.extend_from_slice(post_msg_queue_hash.as_slice());
    payload.extend(initial_block_number.to_be_bytes());
    payload.extend(num_blocks.to_be_bytes());
    assert_eq!(payload.len(), 74);
    for info in &chunk_infos {
        for ctx in &info.block_ctxs {
            payload.extend(ctx.to_bytes());
        }
    }
    assert_eq!(payload.len(), 74 + 52 * num_blocks as usize);
    payload.extend(chunk_tx_bytes);

    let compressed_payload = vm_zstd::zstd_encode(&payload);
    assert!(
        compressed_payload.len() <= N_BLOB_BYTES - 5,
        "compressed batch payload too big"
    );

    let heading = compressed_payload.len() as u32 + ((version.stf_version as u32) << 24);
    let mut blob_bytes = Vec::from(heading.to_be_bytes());
    blob_bytes.push(1u8); // compressed flag
    blob_bytes.extend(compressed_payload);
    blob_bytes.resize(N_BLOB_BYTES, 0);

    // Compute the real EIP-4844 KZG commitment/proof for this blob.
    let blob_for_kzg = scroll_zkvm_types_batch::utils::point_eval::to_blob(&blob_bytes);
    let kzg_commitment = scroll_zkvm_types_batch::utils::point_eval::blob_to_kzg_commitment(&blob_for_kzg);
    let blob_versioned_hash = scroll_zkvm_types_batch::utils::point_eval::get_versioned_hash(&kzg_commitment);

    let envelope = EnvelopeV7::from_slice(&blob_bytes);
    let challenge_digest = envelope.challenge_digest(blob_versioned_hash);
    let (kzg_proof, _y) = scroll_zkvm_types_batch::utils::point_eval::get_kzg_proof(&blob_for_kzg, challenge_digest);

    let point_eval_witness = scroll_zkvm_types_batch::build_point_eval_witness(
        *kzg_commitment.to_bytes(),
        *kzg_proof.to_bytes(),
    );

    let reference_header = ReferenceHeader::V7_V8_V9(BatchHeaderV7 {
        version: version.as_version_byte(),
        batch_index: 124,
        parent_batch_hash: B256::new([
            0xab, 0xac, 0xad, 0xae, 0xaf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        blob_versioned_hash,
    });

    let chunk_proofs = chunk_infos
        .iter()
        .map(|info| {
            let pi_hash = info.pi_hash_by_version(version);
            AggregationInput {
                public_values: pi_hash
                    .as_slice()
                    .iter()
                    .map(|&b| b as u32)
                    .collect::<Vec<_>>(),
                commitment: ProgramCommitment::default(),
            }
        })
        .collect();

    Ok(BatchWitness {
        version: version.as_version_byte(),
        chunk_proofs,
        chunk_infos,
        reference_header,
        blob_bytes,
        point_eval_witness: Some(point_eval_witness),
        fork_name: version.fork,
    })
}

/// Compute [`BatchInfo`] from a [`BatchWitness`] by validating the batch payload against the
/// chunk infos. This mirrors the logic inside the SP1 batch circuit.
pub fn batch_info_from_witness(witness: &BatchWitness) -> eyre::Result<BatchInfo> {
    match &witness.reference_header {
        ReferenceHeader::V7_V8_V9(header) => {
            let mut blob_bytes = witness.blob_bytes.clone();
            blob_bytes.resize(N_BLOB_BYTES, 0);
            let envelope = EnvelopeV7::from_slice(&blob_bytes);
            let payload = PayloadV7::from_envelope(&envelope);
            let (first, last) = payload.validate(header, &witness.chunk_infos);
            Ok(BatchInfo {
                parent_state_root: first.prev_state_root,
                parent_batch_hash: header.parent_batch_hash,
                state_root: last.post_state_root,
                batch_hash: header.batch_hash(),
                chain_id: last.chain_id,
                withdraw_root: last.withdraw_root,
                prev_msg_queue_hash: first.prev_msg_queue_hash,
                post_msg_queue_hash: last.post_msg_queue_hash,
                encryption_key: None,
            })
        }
        _ => eyre::bail!("only V7 batch headers are supported by the SP1 prover-test helper"),
    }
}

/// Default batch witnesses for a small single-batch bundle.
pub fn preset_batch_witnesses() -> eyre::Result<Vec<BatchWitness>> {
    let range_a = preset_batch_chunk_ranges();
    let chunks_a: Vec<ChunkWitness> = range_a
        .into_iter()
        .map(|r| build_chunk_witness(r.into_iter()))
        .collect::<eyre::Result<Vec<_>>>()?;
    Ok(vec![build_batch_witness(&chunks_a)?])
}

/// Build a [`BundleWitness`] from a slice of batch witnesses.
pub fn build_bundle_witness(batch_witnesses: &[BatchWitness]) -> eyre::Result<BundleWitness> {
    let version = testing_version();
    let batch_infos: Vec<BatchInfo> = batch_witnesses
        .iter()
        .map(batch_info_from_witness)
        .collect::<eyre::Result<Vec<_>>>()?;

    let batch_proofs = batch_infos
        .iter()
        .map(|info| {
            let pi_hash = info.pi_hash_by_version(version);
            AggregationInput {
                public_values: pi_hash
                    .as_slice()
                    .iter()
                    .map(|&b| b as u32)
                    .collect::<Vec<_>>(),
                commitment: ProgramCommitment::default(),
            }
        })
        .collect();

    Ok(BundleWitness {
        version: version.as_version_byte(),
        batch_infos,
        batch_proofs,
        fork_name: version.fork,
    })
}
