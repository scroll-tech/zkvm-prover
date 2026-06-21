use crate::{testing_hardfork, testing_version, testing_version_validium};
use bytesize::ByteSize;
use sbv_core::BlockWitness;
use sbv_primitives::types::consensus::ScrollTransaction;
use alloy_primitives::U256;
use sbv_primitives::{B256, types::eips::Encodable2718};
use scroll_zkvm_types::{
    public_inputs::{ForkName, MultiVersionPublicInputs, Version},
    scroll::{
        batch::{
            BatchHeader, BatchHeaderV6, BatchHeaderV7, BatchHeaderValidium, BatchHeaderValidiumV1,
            BatchInfo, BatchWitness, N_BLOB_BYTES, ReferenceHeader, build_point_eval_witness,
        },
        bundle::{BundleInfo, BundleWitness},
        chunk::{ChunkInfo, ChunkWitness},
    },
    types_agg::AggregationInput,
    utils::{keccak256, point_eval, serialize_vk},
};
use std::env;
use vm_zstd::zstd_encode;

#[allow(dead_code)]
fn final_l1_index(blk: &BlockWitness) -> u64 {
    // Get number of l1 txs. L1 txs can be skipped, so just counting is not enough
    // (The comment copied from scroll-prover, but why the max l1 queue index is always
    // the last one for a chunk, or, is the last l1 never being skipped?)
    blk.transactions
        .iter()
        .filter_map(|tx| tx.queue_index())
        .max()
        .unwrap_or_default()
}

fn blks_tx_bytes<'a>(blks: impl Iterator<Item = &'a BlockWitness>) -> Vec<u8> {
    blks.flat_map(|blk| &blk.transactions)
        .filter(|tx| !tx.is_l1_message())
        .fold(Vec::new(), |mut tx_bytes, tx| {
            tx.encode_2718(&mut tx_bytes);
            tx_bytes
        })
}

#[derive(Clone, Debug)]
pub struct LastHeader {
    pub batch_index: u64,
    pub batch_hash: B256,
    pub version: u8,
    /// legacy field
    pub l1_message_index: u64,
}

impl Default for LastHeader {
    fn default() -> Self {
        // create a default LastHeader according to the dummy value
        // being set in the e2e test in scroll-prover:
        // https://github.com/scroll-tech/scroll-prover/blob/82f8ed3fabee5c3001b0b900cda1608413e621f8/integration/tests/e2e_tests.rs#L203C1-L207C8
        Self {
            batch_index: 123,
            version: testing_version().as_version_byte(),
            batch_hash: B256::new([
                0xab, 0xac, 0xad, 0xae, 0xaf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            l1_message_index: 0,
        }
    }
}

impl From<&ReferenceHeader> for LastHeader {
    fn from(value: &ReferenceHeader) -> Self {
        match value {
            ReferenceHeader::V6(h) => h.into(),
            ReferenceHeader::V7_V8_V9(h) | ReferenceHeader::V8(h) => h.into(),
            ReferenceHeader::Validium(h) => h.into(),
        }
    }
}

impl From<&BatchHeaderV6> for LastHeader {
    fn from(h: &BatchHeaderV6) -> Self {
        Self {
            batch_index: h.batch_index,
            version: h.version,
            batch_hash: h.batch_hash(),
            l1_message_index: h.total_l1_message_popped,
        }
    }
}

impl From<&BatchHeaderV7> for LastHeader {
    fn from(h: &BatchHeaderV7) -> Self {
        Self {
            batch_index: h.batch_index,
            version: h.version,
            batch_hash: h.batch_hash(),
            l1_message_index: 0,
        }
    }
}

impl From<&BatchHeaderValidium> for LastHeader {
    fn from(h: &BatchHeaderValidium) -> Self {
        Self {
            batch_index: h.index(),
            version: h.version(),
            batch_hash: h.batch_hash(),
            l1_message_index: 0,
        }
    }
}

pub fn metadata_from_chunk_witnesses(witness: ChunkWitness) -> eyre::Result<ChunkInfo> {
    witness
        .try_into()
        .map_err(|e| eyre::eyre!("get chunk metadata fail {e}"))
}

pub fn metadata_from_batch_witnesses(witness: &BatchWitness) -> eyre::Result<BatchInfo> {
    Ok(witness.into())
}

pub fn metadata_from_bundle_witnesses(witness: &BundleWitness) -> eyre::Result<BundleInfo> {
    Ok(witness.into())
}

/// Result of folding chunk transaction data.
struct ChunkFoldResult {
    meta_chunk_sizes: Vec<usize>,
    chunk_digests: Vec<B256>,
    chunk_tx_bytes: Vec<u8>,
}

/// Collect tx data from chunks: sizes, keccak digests, and raw bytes.
fn fold_chunk_data(chunks: &[ChunkWitness]) -> ChunkFoldResult {
    chunks.iter().fold(
        ChunkFoldResult {
            meta_chunk_sizes: Vec::new(),
            chunk_digests: Vec::new(),
            chunk_tx_bytes: Vec::new(),
        },
        |mut acc, chunk_wit| {
            let tx_bytes = blks_tx_bytes(chunk_wit.blocks.iter());
            acc.meta_chunk_sizes.push(tx_bytes.len());
            acc.chunk_digests.push(keccak256(&tx_bytes));
            acc.chunk_tx_bytes.extend(tx_bytes);
            acc
        },
    )
}

/// Verify that chunk tx_data digests match the expected values in chunk_infos.
fn verify_chunk_digests(chunk_digests: &[B256], chunk_infos: &[ChunkInfo]) {
    for (digest, chunk_info) in chunk_digests.iter().zip(chunk_infos) {
        assert_eq!(digest, &chunk_info.tx_data_digest);
    }
}

/// Build AggregationInput list from chunk_infos and the prover verification key.
fn build_chunk_agg_inputs(
    chunk_infos: &[ChunkInfo],
    prover_vk: &[u8],
    version: Version,
) -> Vec<AggregationInput> {
    let commitment = serialize_vk::deserialize(prover_vk);
    chunk_infos
        .iter()
        .map(|chunk_info| {
            let pi_hash = chunk_info.pi_hash_by_version(version);
            AggregationInput {
                public_values: pi_hash.as_slice().iter().map(|&b| b as u32).collect(),
                commitment,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// EuclidV1 batch header builder
// ---------------------------------------------------------------------------
fn build_v6_ref_header(
    chunks: &[ChunkWitness],
    chunk_infos: &[ChunkInfo],
    last_header: &LastHeader,
    x: U256,
    z: U256,
    blob_versioned_hash: B256,
) -> ReferenceHeader {
    let last_l1_message_index: u64 = chunks
        .iter()
        .flat_map(|t| &t.blocks)
        .map(final_l1_index)
        .reduce(|last, cur| if cur == 0 { last } else { cur })
        .expect("at least one chunk");
    let last_l1_message_index = if last_l1_message_index == 0 {
        last_header.l1_message_index
    } else {
        last_l1_message_index
    };

    let last_block_timestamp = chunks.last().map_or(0u64, |t| {
        t.blocks.last().map_or(0, |trace| trace.header.timestamp)
    });

    let point_evaluations = [x, z];
    let data_hash = keccak256(
        chunk_infos
            .iter()
            .map(|c| &c.data_hash)
            .fold(Vec::new(), |mut bytes, h| {
                bytes.extend_from_slice(&h.0);
                bytes
            }),
    );

    ReferenceHeader::V6(BatchHeaderV6 {
        version: last_header.version,
        batch_index: last_header.batch_index + 1,
        l1_message_popped: last_l1_message_index - last_header.l1_message_index,
        last_block_timestamp,
        total_l1_message_popped: last_l1_message_index,
        parent_batch_hash: last_header.batch_hash,
        data_hash,
        blob_versioned_hash,
        blob_data_proof: point_evaluations.map(|u| B256::new(u.to_be_bytes())),
    })
}

// ---------------------------------------------------------------------------
// V2+ batch header builder (EuclidV2 and later forks)
// ---------------------------------------------------------------------------
fn build_v7_ref_header(
    last_header: &LastHeader,
    blob_versioned_hash: B256,
) -> ReferenceHeader {
    ReferenceHeader::V7_V8_V9(BatchHeaderV7 {
        version: last_header.version,
        batch_index: last_header.batch_index + 1,
        parent_batch_hash: last_header.batch_hash,
        blob_versioned_hash,
    })
}

// ---------------------------------------------------------------------------
// Builder for legacy chunk-size metadata bytes
// ---------------------------------------------------------------------------
fn build_meta_chunk_bytes(meta_chunk_sizes: &[usize], num_chunks: usize) -> Vec<u8> {
    const LEGACY_MAX_CHUNKS: usize = 45;
    let valid_chunk_size = num_chunks as u16;
    meta_chunk_sizes
        .iter()
        .copied()
        .chain(std::iter::repeat(0))
        .take(LEGACY_MAX_CHUNKS)
        .fold(
            Vec::from(valid_chunk_size.to_be_bytes()),
            |mut bytes, len| {
                bytes.extend_from_slice(&(len as u32).to_be_bytes());
                bytes
            },
        )
}

/// Build a scroll (non-validium) batch witness.
pub fn build_batch_witnesses(
    chunks: &[ChunkWitness],
    prover_vk: &[u8],
    last_header: LastHeader,
) -> eyre::Result<BatchWitness> {
    let chunk_infos = chunks
        .iter()
        .cloned()
        .map(metadata_from_chunk_witnesses)
        .collect::<eyre::Result<Vec<_>>>()?;

    let fold = fold_chunk_data(chunks);
    verify_chunk_digests(&fold.chunk_digests, &chunk_infos);

    let version = testing_version();
    let is_v2_plus = version.fork >= ForkName::EuclidV2;

    // Build payload header for V2+ forks
    let mut payload = if is_v2_plus {
        let num_blocks = chunks.iter().map(|w| w.blocks.len()).sum::<usize>() as u16;
        let prev_msg_queue_hash = chunks[0].prev_msg_queue_hash;
        let initial_block_number = chunks[0].blocks[0].header.number;
        let post_msg_queue_hash = chunk_infos
            .last()
            .expect("at least one chunk")
            .post_msg_queue_hash;

        let mut p = Vec::new();
        p.extend_from_slice(prev_msg_queue_hash.as_slice());
        p.extend_from_slice(post_msg_queue_hash.as_slice());
        p.extend(initial_block_number.to_be_bytes());
        p.extend(num_blocks.to_be_bytes());
        assert_eq!(p.len(), 74);
        for chunk_info in &chunk_infos {
            for ctx in &chunk_info.block_ctxs {
                p.extend(ctx.to_bytes());
            }
        }
        assert_eq!(p.len(), 74 + 52 * num_blocks as usize);
        p
    } else {
        build_meta_chunk_bytes(&fold.meta_chunk_sizes, chunks.len())
    };
    payload.extend(fold.chunk_tx_bytes);

    let compressed_payload = zstd_encode(&payload);
    if compressed_payload.len() > N_BLOB_BYTES - 5 {
        return Err(eyre::eyre!(
            "compression payload of batch too big: len={}",
            compressed_payload.len()
        ));
    }

    let heading = compressed_payload.len() as u32 + ((version.stf_version as u32) << 24);
    let blob_bytes = if is_v2_plus {
        let mut b = Vec::from(heading.to_be_bytes());
        b.push(1u8);
        b.extend(compressed_payload);
        b.resize(4096 * 31, 0);
        b
    } else {
        let mut b = heading.to_be_bytes().to_vec();
        b.push(1u8);
        b.extend(compressed_payload);
        b
    };

    let kzg_blob = point_eval::to_blob(&blob_bytes);
    let kzg_commitment = point_eval::blob_to_kzg_commitment(&kzg_blob);
    let blob_versioned_hash = point_eval::get_versioned_hash(&kzg_commitment);

    let challenge_preimage = if is_v2_plus {
        let mut preimage = keccak256(&blob_bytes).to_vec();
        preimage.extend(blob_versioned_hash.0);
        preimage
    } else {
        let meta_chunk_bytes = build_meta_chunk_bytes(&fold.meta_chunk_sizes, chunks.len());
        let mut preimage = Vec::from(keccak256(&meta_chunk_bytes).0);
        let last_digest = fold.chunk_digests.last().expect("at least one chunk");
        preimage.extend(
            fold.chunk_digests
                .iter()
                .chain(std::iter::repeat(last_digest))
                .take(45)
                .fold(Vec::new(), |mut ret, digest| {
                    ret.extend_from_slice(&digest.0);
                    ret
                }),
        );
        preimage.extend_from_slice(blob_versioned_hash.as_slice());
        preimage
    };
    let challenge_digest = keccak256(&challenge_preimage);

    let x = point_eval::get_x_from_challenge(challenge_digest);
    let (kzg_proof, z) = point_eval::get_kzg_proof(&kzg_blob, challenge_digest);

    let reference_header = match testing_hardfork() {
        ForkName::EuclidV1 => build_v6_ref_header(
            chunks,
            &chunk_infos,
            &last_header,
            x,
            z,
            blob_versioned_hash,
        ),
        _ => build_v7_ref_header(&last_header, blob_versioned_hash),
    };

    let chunk_proofs = build_chunk_agg_inputs(&chunk_infos, prover_vk, version);
    let point_eval_witness = build_point_eval_witness(
        *kzg_commitment.to_bytes().as_ref(),
        *kzg_proof.to_bytes().as_ref(),
    );

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

/// Build a validium batch witness (no blob or KZG).
pub fn build_batch_witnesses_validium(
    chunks: &[ChunkWitness],
    prover_vk: &[u8],
    last_header: LastHeader,
) -> eyre::Result<BatchWitness> {
    let chunk_infos = chunks
        .iter()
        .cloned()
        .map(metadata_from_chunk_witnesses)
        .collect::<eyre::Result<Vec<_>>>()?;

    let fold = fold_chunk_data(chunks);
    verify_chunk_digests(&fold.chunk_digests, &chunk_infos);

    let version = testing_version_validium();
    let last_chunk = chunk_infos.last().expect("at least 1 chunk in batch");
    let reference_header =
        ReferenceHeader::Validium(BatchHeaderValidium::V1(BatchHeaderValidiumV1 {
            version: version.stf_version as u8,
            batch_index: last_header.batch_index + 1,
            parent_batch_hash: last_header.batch_hash,
            post_state_root: last_chunk.post_state_root,
            withdraw_root: last_chunk.withdraw_root,
            commitment: last_chunk.post_blockhash,
        }));

    let chunk_proofs = build_chunk_agg_inputs(&chunk_infos, prover_vk, version);

    Ok(BatchWitness {
        version: version.as_version_byte(),
        chunk_proofs,
        chunk_infos,
        reference_header,
        blob_bytes: Vec::default(),
        point_eval_witness: None,
        fork_name: version.fork,
    })
}

#[test]
fn test_build_and_parse_batch_task() -> eyre::Result<()> {
    use crate::testers::chunk::ChunkTaskGenerator;
    use scroll_zkvm_types::scroll::batch::{self, Envelope, Payload};

    let witness = match testing_hardfork() {
        ForkName::EuclidV2 => ChunkTaskGenerator {
            block_range: (1..=4).collect(),
            ..Default::default()
        },
        ForkName::EuclidV1 => ChunkTaskGenerator {
            block_range: (12508460..=12508463).collect(),
            ..Default::default()
        },
        ForkName::Feynman => ChunkTaskGenerator {
            block_range: (16525000..=16525003).collect(),
            ..Default::default()
        },
        ForkName::Galileo => ChunkTaskGenerator {
            block_range: (20239156..=20239192).collect(),
            ..Default::default()
        },
        ForkName::GalileoV2 => ChunkTaskGenerator {
            block_range: (20239240..=20239245).collect(),
            ..Default::default()
        },
    }
    .get_or_build_witness()?;

    let witnesses = [witness];

    let task_wit = build_batch_witnesses(
        &witnesses,
        &[0u8; 64], // use a default, all zero vk
        Default::default(),
    )?;

    let infos = task_wit.chunk_infos.as_slice();

    match &task_wit.reference_header {
        ReferenceHeader::V6(h) => {
            let enveloped = batch::EnvelopeV6::from_slice(&task_wit.blob_bytes);
            <batch::PayloadV6 as Payload>::from_envelope(&enveloped).validate(h, infos);
        }
        ReferenceHeader::V7_V8_V9(h) => {
            let enveloped = batch::EnvelopeV7::from_slice(&task_wit.blob_bytes);
            <batch::PayloadV7 as Payload>::from_envelope(&enveloped).validate(h, infos);
        }
        ReferenceHeader::V8(h) => {
            let enveloped = batch::EnvelopeV7::from_slice(&task_wit.blob_bytes);
            <batch::PayloadV7 as Payload>::from_envelope(&enveloped).validate(h, infos);
        }
        ReferenceHeader::Validium(_h) => {
            todo!()
        }
    }

    Ok(())
}

pub fn get_rayon_threads() -> usize {
    const MEMORY_PRESERVED_EACH_THREAD: u64 = 10 * 1024 * 1024 * 1024; // 10GB

    if let Some(threads) = env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        eprintln!("RAYON_NUM_THREADS set, using {} threads", threads);
        return threads;
    }

    let memory_preserved_each_thread = env::var("MEMORY_PRESERVED_EACH_THREAD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(MEMORY_PRESERVED_EACH_THREAD);
    eprintln!(
        "preserving {} bytes for each thread",
        ByteSize::b(memory_preserved_each_thread).display().iec()
    );

    let mut system = sysinfo::System::new();
    system.refresh_cpu_list(sysinfo::CpuRefreshKind::nothing().with_frequency());
    system.refresh_memory_specifics(sysinfo::MemoryRefreshKind::nothing().with_ram());
    let free_memory = system.free_memory();
    let max_threads = (free_memory / MEMORY_PRESERVED_EACH_THREAD) as usize;
    let n_cpus = system.cpus().len();
    let threads = max_threads.clamp(1, n_cpus);
    eprintln!(
        "RAYON_NUM_THREADS not set, using {} threads ({} CPUs, {} free memory)",
        threads, n_cpus, free_memory
    );
    threads
}
