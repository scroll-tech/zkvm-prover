use alloy_primitives::B256;
use rkyv::util::AlignedVec;
use sbv_core::verifier::StateCommitMode;
use sbv_primitives::{U256, types::BlockWitness};
use std::collections::HashSet;
use types_base::{fork_name::ForkName, public_inputs::chunk::ChunkInfo};

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
pub struct ChunkWitnessEuclid {
    /// The block witness for each block in the chunk.
    pub blocks: Vec<BlockWitness>,
    /// The on-chain rolling L1 message queue hash before enqueueing any L1 msg tx from the chunk.
    pub prev_msg_queue_hash: B256,
    /// The code version specify the chain spec
    pub fork_name: ForkName,
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
pub struct ChunkWitness {
    /// The block witness for each block in the chunk.
    pub blocks: Vec<BlockWitness>,
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
    pub fn new(blocks: &[BlockWitness], prev_msg_queue_hash: B256, fork_name: ForkName) -> Self {
        let num_codes = blocks.iter().map(|w| w.codes.len()).sum();
        let num_states = blocks.iter().map(|w| w.states.len()).sum();
        let mut codes = HashSet::with_capacity(num_codes);
        let mut states = HashSet::with_capacity(num_states);

        let blocks: Vec<BlockWitness> = blocks
            .iter()
            .map(|block| BlockWitness {
                chain_id: block.chain_id,
                header: block.header.clone(),
                pre_state_root: block.pre_state_root,
                transaction: block.transaction.clone(),
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
            state_commit_mode: StateCommitMode::Auto,
        }
    }
    /// Convert the `ChunkWitness` into a `ChunkWitnessEuclid`.
    pub fn into_euclid(self) -> ChunkWitnessEuclid {
        ChunkWitnessEuclid {
            blocks: self.blocks,
            prev_msg_queue_hash: self.prev_msg_queue_hash,
            fork_name: self.fork_name,
        }
    }
    pub fn bincode_serialize(
        &self,
        guest_version: Option<ForkName>,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let config = bincode::config::standard();
        bincode::serde::encode_to_vec(&self, config)
    }
    /// `guest_version` is related to the guest program.
    /// It is not always same with the evm hardfork.
    /// For example, a `Feynman` guest program can execute `EuclidV2` blocks.
    /// While in realworld, we keep them same.
    /// Only during development, we may use different versions.
    pub fn rkyv_serialize(
        &self,
        guest_version: Option<ForkName>,
    ) -> Result<AlignedVec, rkyv::rancor::Error> {
        let guest_version = guest_version.unwrap_or(self.fork_name);
        if guest_version >= ForkName::Feynman {
            // Use the new rkyv serialization for Feynman and later forks
            rkyv::to_bytes::<rkyv::rancor::Error>(self)
        } else {
            // Use the old rkyv serialization for earlier forks
            rkyv::to_bytes::<rkyv::rancor::Error>(&self.clone().into_euclid())
        }
    }

    pub fn stats(&self) -> ChunkDetails {
        let num_blocks = self.blocks.len();
        let num_txs = self
            .blocks
            .iter()
            .map(|b| b.transaction.len())
            .sum::<usize>();
        let total_gas_used = self.blocks.iter().map(|b| b.header.gas_used).sum::<u64>();

        ChunkDetails {
            num_blocks,
            num_txs,
            total_gas_used,
        }
    }
}

impl TryFrom<&ChunkWitness> for ChunkInfo {
    type Error = String;

    fn try_from(value: &ChunkWitness) -> Result<Self, Self::Error> {
        crate::execute(value)
    }
}
