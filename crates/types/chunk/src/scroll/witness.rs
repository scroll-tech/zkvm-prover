use super::types::validium::SecretKey;
use alloy_primitives::B256;
use sbv_core::{verifier::StateCommitMode, witness::BlockWitness};
use sbv_primitives::U256;
use sbv_primitives::types::consensus::TxL1Message;
use sbv_trie::PartialStateTrie;
use std::collections::HashSet;
use types_base::version::Version;
use types_base::{fork_name::ForkName, public_inputs::chunk::ChunkInfo};

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChunkWitness {
    /// Version byte as per [version][types_base::version].
    pub version: u8,
    /// The block witness for each block in the chunk.
    pub blocks: Vec<BlockWitness>,
    /// The on-chain rolling L1 message queue hash before enqueueing any L1 msg tx from the chunk.
    pub prev_msg_queue_hash: B256,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
    /// The compression ratios for each block in the chunk.
    pub compression_ratios: Vec<Vec<U256>>,
    /// Validium encrypted txs and secret key if this is a validium chain.
    pub validium: Option<ValidiumInputs>,
}

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChunkWitnessWithRspTrie {
    /// Version byte as per [version][types_base::version].
    pub version: u8,
    /// The block witness for each block in the chunk.
    pub blocks: Vec<BlockWitness>,
    /// The on-chain rolling L1 message queue hash before enqueueing any L1 msg tx from the chunk.
    pub prev_msg_queue_hash: B256,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
    /// The compression ratios for each block in the chunk.
    pub compression_ratios: Vec<Vec<U256>>,
    /// The cached partial state trie for the chunk.
    pub cached_trie: PartialStateTrie,
    /// Validium encrypted txs and secret key if this is a validium chain.
    pub validium: Option<ValidiumInputs>,
}

/// The validium inputs for the chunk witness.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ValidiumInputs {
    /// The validium transactions for each block in the chunk.
    pub validium_txs: Vec<Vec<TxL1Message>>,
    /// The secret key used for decrypting validium transactions.
    pub secret_key: Box<[u8]>,
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
    pub state_commit_mode: StateCommitMode,
}

#[derive(Clone, Debug)]
pub struct ChunkDetails {
    pub num_blocks: usize,
    pub num_txs: usize,
    pub total_gas_used: u64,
}

impl ChunkWitness {
    pub fn new_scroll(
        version: u8,
        blocks: &[BlockWitness],
        prev_msg_queue_hash: B256,
        fork_name: ForkName,
    ) -> Self {
        Self::new(version, blocks, prev_msg_queue_hash, fork_name, None)
    }

    pub fn new_validium(
        version: u8,
        blocks: &[BlockWitness],
        prev_msg_queue_hash: B256,
        fork_name: ForkName,
        validium_txs: Vec<Vec<TxL1Message>>,
        secret_key: SecretKey,
    ) -> Self {
        Self::new(
            version,
            blocks,
            prev_msg_queue_hash,
            fork_name,
            Some(ValidiumInputs {
                validium_txs,
                secret_key: secret_key.to_bytes(),
            }),
        )
    }

    pub fn new(
        version: u8,
        blocks: &[BlockWitness],
        prev_msg_queue_hash: B256,
        fork_name: ForkName,
        validium: Option<ValidiumInputs>,
    ) -> Self {
        let num_codes = blocks.iter().map(|w| w.codes.len()).sum();
        let mut codes = HashSet::with_capacity(num_codes);

        let num_states = blocks.iter().map(|w| w.states.len()).sum();
        let mut states = HashSet::with_capacity(num_states);

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
            version,
            blocks,
            prev_msg_queue_hash,
            fork_name,
            compression_ratios,
            validium,
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

    pub fn version(&self) -> Version {
        Version::from(self.version)
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
            state_commit_mode: StateCommitMode::Auto,
        }
    }
}

impl From<ChunkWitness> for ChunkWitnessWithRspTrie {
    fn from(mut value: ChunkWitness) -> Self {
        let pre_state_root = value
            .blocks
            .first()
            .expect("at least one block")
            .prev_state_root;
        let cached_trie = PartialStateTrie::new(
            pre_state_root,
            value.blocks.iter().flat_map(|w| w.states.iter()),
        )
        .expect("trie from witness");

        for block in value.blocks.iter_mut() {
            block.states.clear();
        }

        ChunkWitnessWithRspTrie {
            version: value.version,
            blocks: value.blocks,
            prev_msg_queue_hash: value.prev_msg_queue_hash,
            fork_name: value.fork_name,
            compression_ratios: value.compression_ratios,
            cached_trie,
            validium: value.validium,
        }
    }
}
