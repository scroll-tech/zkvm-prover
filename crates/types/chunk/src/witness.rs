use alloy_primitives::B256;
#[allow(deprecated)]
use sbv_core::verifier::StateCommitMode;
use sbv_primitives::{U256, types::BlockWitness};
use std::collections::{HashSet};
use sbv_kv::nohash::NoHashMap;
use sbv_primitives::chainspec::{build_chain_spec_force_hardfork, Chain};
use sbv_primitives::hardforks::Hardfork;
use sbv_trie::{BlockWitnessTrieExt, PartialStateTrie};
use types_base::{fork_name::ForkName, public_inputs::chunk::ChunkInfo};

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ChunkWitness {
    /// The block witness for each block in the chunk.
    pub blocks: Vec<BlockWitness>,
    /// The on-chain rolling L1 message queue hash before enqueueing any L1 msg tx from the chunk.
    pub prev_msg_queue_hash: B256,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
    /// The compression ratios for each block in the chunk.
    pub compression_ratios: Vec<Vec<U256>>,
    /// The partial state trie constructed outside the circuit.
    pub cached_trie: PartialStateTrie,
}

/// The witness type accepted by the chunk-circuit.
#[derive(
    Clone,
    Debug,
    serde::Deserialize,
    serde::Serialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct LegacyChunkWitness {
    /// The block witness for each block in the chunk.
    pub blocks: Vec<sbv_primitives::legacy_types::BlockWitness>,
    /// The on-chain rolling L1 message queue hash before enqueueing any L1 msg tx from the chunk.
    pub prev_msg_queue_hash: B256,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
    /// The compression ratios for each block in the chunk.
    pub compression_ratios: Vec<Vec<U256>>,
    /// The mode of state commitment for the chunk.
    #[allow(deprecated)]
    pub state_commit_mode: StateCommitMode,
}

#[derive(Clone, Debug)]
pub struct ChunkDetails {
    pub num_blocks: usize,
    pub num_txs: usize,
    pub total_gas_used: u64,
}

impl ChunkWitness {
    pub fn new(blocks: &[BlockWitness], prev_msg_queue_hash: B256, fork_name: ForkName) -> Self {
        let num_codes = blocks.iter().map(|w| w.codes.len()).sum();
        let num_states = blocks.iter().map(|w| w.states.len()).sum();
        let mut codes = HashSet::with_capacity(num_codes);
        let mut states = HashSet::with_capacity(num_states);

        let chain = Chain::from_id(blocks[0].chain_id);
        let chain_spec = build_chain_spec_force_hardfork(
            chain,
            match fork_name {
                ForkName::EuclidV1 => Hardfork::Euclid,
                ForkName::EuclidV2 => Hardfork::EuclidV2,
                ForkName::Feynman => Hardfork::Feynman,
            },
        );

        let result = sbv_core::verifier::run(blocks.to_vec(), chain_spec, None::<Vec<Vec<U256>>>, None).expect("");
        let access_list = result.access_list.unwrap();
        let mut nodes_provider = NoHashMap::with_capacity_and_hasher(num_states, Default::default());
        blocks.import_nodes(&mut nodes_provider);
        let cached_trie = PartialStateTrie::open_preloaded(&nodes_provider, blocks[0].prev_state_root, access_list)
            .expect("failed to open trie from the first block's prev_state_root");

        let blocks: Vec<BlockWitness> = blocks
            .iter()
            .map(|block| BlockWitness {
                chain_id: block.chain_id,
                header: block.header.clone(),
                prev_state_root: block.prev_state_root,
                transactions: block.transactions.clone(),
                withdrawals: block.withdrawals.clone(),
                states: block
                    .states
                    .iter()
                    .filter(|s| states.insert(*s))
                    .cloned()
                    .collect(),
                codes: block
                    .codes
                    .iter()
                    .filter(|c| codes.insert(*c))
                    .cloned()
                    .collect(),
            })
            .collect();
        let compression_ratios = blocks
            .iter()
            .map(|block| block.compression_ratios())
            .collect();

        Self {
            blocks,
            prev_msg_queue_hash,
            fork_name,
            compression_ratios,
            cached_trie,
        }
    }

    pub fn stats(&self) -> ChunkDetails {
        let num_blocks = self.blocks.len();
        let num_txs = self
            .blocks
            .iter()
            .map(|b| b.transactions.len())
            .sum::<usize>();
        let total_gas_used = self.blocks.iter().map(|b| b.header.gas_used).sum::<u64>();

        ChunkDetails {
            num_blocks,
            num_txs,
            total_gas_used,
        }
    }
}

impl TryFrom<ChunkWitness> for ChunkInfo {
    type Error = String;

    fn try_from(value: ChunkWitness) -> Result<Self, Self::Error> {
        crate::execute(value)
    }
}

impl From<ChunkWitness> for LegacyChunkWitness {
    fn from(value: ChunkWitness) -> Self {
        LegacyChunkWitness {
            blocks: value
                .blocks
                .into_iter()
                .map(|block| block.into_legacy())
                .collect(),
            prev_msg_queue_hash: value.prev_msg_queue_hash,
            fork_name: value.fork_name,
            compression_ratios: value.compression_ratios,
            #[allow(deprecated)]
            state_commit_mode: StateCommitMode::Auto,
        }
    }
}
