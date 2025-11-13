use crate::{testing_hardfork, testing_version, testing_version_validium};
use bytesize::ByteSize;
use sbv_core::BlockWitness;
use sbv_primitives::types::consensus::ScrollTransaction;
use sbv_primitives::{B256, types::eips::Encodable2718};
use scroll_zkvm_types::batch::build_point_eval_witness;
use scroll_zkvm_types::{
    batch::{
        BatchHeader, BatchHeaderV6, BatchHeaderV7, BatchHeaderValidium, BatchHeaderValidiumV1,
        BatchInfo, BatchWitness, ReferenceHeader,
    },
    bundle::{BundleInfo, BundleWitness},
    chunk::{ChunkInfo, ChunkWitness},
    public_inputs::{ForkName, MultiVersionPublicInputs},
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
            version: testing_hardfork().to_protocol_version(),
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
            ReferenceHeader::V7(h) => h.into(),
            ReferenceHeader::V8(h) => h.into(),
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

pub fn build_batch_witnesses(
    chunks: &[ChunkWitness],
    prover_vk: &[u8], // notice we supppose all proof is (would be) generated from the same prover
    last_header: LastHeader,
) -> eyre::Result<BatchWitness> {
    let chunk_infos = chunks
        .iter()
        .cloned()
        .map(metadata_from_chunk_witnesses)
        .collect::<eyre::Result<Vec<_>>>()?;

    // collect tx bytes from chunk tasks
    let (meta_chunk_sizes, chunk_digests, chunk_tx_bytes) = chunks.iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut meta_chunk_sizes, mut chunk_digests, mut payload_bytes), chunk_wit| {
            let tx_bytes = blks_tx_bytes(chunk_wit.blocks.iter());
            meta_chunk_sizes.push(tx_bytes.len());
            chunk_digests.push(keccak256(&tx_bytes));
            payload_bytes.extend(tx_bytes);
            (meta_chunk_sizes, chunk_digests, payload_bytes)
        },
    );

    // sanity check, verify the correction of execute
    for (digest, chunk_info) in chunk_digests.iter().zip(chunk_infos.as_slice()) {
        assert_eq!(digest, &chunk_info.tx_data_digest);
    }

    const LEGACY_MAX_CHUNKS: usize = 45;

    let meta_chunk_bytes = {
        let valid_chunk_size = chunks.len() as u16;
        meta_chunk_sizes
            .into_iter()
            .chain(std::iter::repeat(0))
            .take(LEGACY_MAX_CHUNKS)
            .fold(
                Vec::from(valid_chunk_size.to_be_bytes()),
                |mut bytes, len| {
                    bytes.extend_from_slice(&(len as u32).to_be_bytes());
                    bytes
                },
            )
    };

    // collect all data together for payload
    let mut payload = if testing_hardfork() >= ForkName::EuclidV2 {
        Vec::new()
    } else {
        meta_chunk_bytes.clone()
    };

    let version = testing_version();
    if version.fork >= ForkName::EuclidV2 {
        let num_blocks = chunks.iter().map(|w| w.blocks.len()).sum::<usize>() as u16;
        let prev_msg_queue_hash = chunks[0].prev_msg_queue_hash;
        let initial_block_number = chunks[0].blocks[0].header.number;
        let post_msg_queue_hash = chunk_infos
            .last()
            .expect("at least one chunk")
            .post_msg_queue_hash;

        payload.extend_from_slice(prev_msg_queue_hash.as_slice());
        payload.extend_from_slice(post_msg_queue_hash.as_slice());
        payload.extend(initial_block_number.to_be_bytes());
        payload.extend(num_blocks.to_be_bytes());
        assert_eq!(payload.len(), 74);
        for chunk_info in &chunk_infos {
            for ctx in &chunk_info.block_ctxs {
                payload.extend(ctx.to_bytes());
            }
        }
        assert_eq!(payload.len(), 74 + 52 * num_blocks as usize);
    }
    payload.extend(chunk_tx_bytes);
    // compress ...
    let compressed_payload = zstd_encode(&payload);

    let heading = compressed_payload.len() as u32 + ((version.codec() as u32) << 24);

    let blob_bytes = if version.fork >= ForkName::EuclidV2 {
        let mut blob_bytes = Vec::from(heading.to_be_bytes());
        blob_bytes.push(1u8); // compressed flag
        blob_bytes.extend(compressed_payload);
        blob_bytes.resize(4096 * 31, 0);
        blob_bytes
    } else {
        let mut blob_bytes = vec![1];
        blob_bytes.extend(compressed_payload);
        blob_bytes
    };

    let kzg_blob = point_eval::to_blob(&blob_bytes);
    let kzg_commitment = point_eval::blob_to_kzg_commitment(&kzg_blob);
    let blob_versioned_hash = point_eval::get_versioned_hash(&kzg_commitment);

    // preimage = keccak(payload) + blob_versioned_hash
    let challenge_preimage = if testing_hardfork() >= ForkName::EuclidV2 {
        let mut challenge_preimage = keccak256(&blob_bytes).to_vec();
        challenge_preimage.extend(blob_versioned_hash.0);
        challenge_preimage
    } else {
        let mut challenge_preimage = Vec::from(keccak256(&meta_chunk_bytes).0);
        let last_digest = chunk_digests.last().expect("at least we have one");
        challenge_preimage.extend(
            chunk_digests
                .iter()
                .chain(std::iter::repeat(last_digest))
                .take(LEGACY_MAX_CHUNKS)
                .fold(Vec::new(), |mut ret, digest| {
                    ret.extend_from_slice(&digest.0);
                    ret
                }),
        );
        challenge_preimage.extend_from_slice(blob_versioned_hash.as_slice());
        challenge_preimage
    };
    let challenge_digest = keccak256(&challenge_preimage);

    let x = point_eval::get_x_from_challenge(challenge_digest);
    let (kzg_proof, z) = point_eval::get_kzg_proof(&kzg_blob, challenge_digest);

    let reference_header: ReferenceHeader = match testing_hardfork() {
        ForkName::EuclidV1 => {
            // collect required fields for batch header
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
                    .map(|chunk_info| &chunk_info.data_hash)
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
        ForkName::EuclidV2 => {
            use scroll_zkvm_types::batch::BatchHeaderV7;
            let _ = x + z;
            ReferenceHeader::V7(BatchHeaderV7 {
                version: last_header.version,
                batch_index: last_header.batch_index + 1,
                parent_batch_hash: last_header.batch_hash,
                blob_versioned_hash,
            })
        }
        ForkName::Feynman | ForkName::Galileo => {
            use scroll_zkvm_types::batch::BatchHeaderV8;
            let _ = x + z;
            ReferenceHeader::V8(BatchHeaderV8 {
                version: last_header.version,
                batch_index: last_header.batch_index + 1,
                parent_batch_hash: last_header.batch_hash,
                blob_versioned_hash,
            })
        }
    };

    let commitment = serialize_vk::deserialize(prover_vk);
    let chunk_proofs = chunk_infos
        .iter()
        .map(|chunk_info| {
            let pi_hash = chunk_info.pi_hash_by_version(version);
            AggregationInput {
                public_values: pi_hash
                    .as_slice()
                    .iter()
                    .map(|&b| b as u32)
                    .collect::<Vec<_>>(),
                commitment: commitment.clone(),
            }
        })
        .collect::<Vec<_>>();

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

pub fn build_batch_witnesses_validium(
    chunks: &[ChunkWitness],
    prover_vk: &[u8], // notice we supppose all proof is (would be) generated from the same prover
    last_header: LastHeader,
) -> eyre::Result<BatchWitness> {
    let chunk_infos = chunks
        .iter()
        .cloned()
        .map(metadata_from_chunk_witnesses)
        .collect::<eyre::Result<Vec<_>>>()?;

    // collect tx bytes from chunk tasks
    let (_, chunk_digests, _) = chunks.iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut meta_chunk_sizes, mut chunk_digests, mut payload_bytes), chunk_wit| {
            let tx_bytes = blks_tx_bytes(chunk_wit.blocks.iter());
            meta_chunk_sizes.push(tx_bytes.len());
            chunk_digests.push(keccak256(&tx_bytes));
            payload_bytes.extend(tx_bytes);
            (meta_chunk_sizes, chunk_digests, payload_bytes)
        },
    );

    // sanity check, verify the correction of execute
    for (digest, chunk_info) in chunk_digests.iter().zip(chunk_infos.as_slice()) {
        assert_eq!(digest, &chunk_info.tx_data_digest);
    }

    // collect all data together for payload
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

    let commitment = serialize_vk::deserialize(prover_vk);
    let chunk_proofs = chunk_infos
        .iter()
        .map(|chunk_info| {
            let pi_hash = chunk_info.pi_hash_by_version(version);
            AggregationInput {
                public_values: pi_hash
                    .as_slice()
                    .iter()
                    .map(|&b| b as u32)
                    .collect::<Vec<_>>(),
                commitment: commitment.clone(),
            }
        })
        .collect::<Vec<_>>();

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
    use scroll_zkvm_types::batch::{self, Envelope, Payload};

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
        ReferenceHeader::V7(h) => {
            let enveloped = batch::EnvelopeV7::from_slice(&task_wit.blob_bytes);
            <batch::PayloadV7 as Payload>::from_envelope(&enveloped).validate(h, infos);
        }
        ReferenceHeader::V8(h) => {
            let enveloped = batch::EnvelopeV8::from_slice(&task_wit.blob_bytes);
            <batch::PayloadV8 as Payload>::from_envelope(&enveloped).validate(h, infos);
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
