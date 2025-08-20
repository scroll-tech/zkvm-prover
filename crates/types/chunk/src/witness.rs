use alloy_primitives::B256;
use rkyv::util::AlignedVec;
use sbv_core::verifier::StateCommitMode;
use sbv_primitives::types::consensus::TxL1Message;
use sbv_primitives::types::reth::primitives::{Block, RecoveredBlock};
use sbv_primitives::{U256, types::BlockWitness};
use std::collections::HashSet;
use std::iter;
use types_base::fork_name::ArchivedForkName;
use types_base::public_inputs::chunk::ChunkExt;
use types_base::public_inputs::chunk::validium::{QueueTransaction, SecretKey};
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
pub struct ChunkWitnessFeynman {
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
    /// Validium encrypted txs and secret key if this is a validium chain.
    pub validium: Option<ValidiumInputs>,
}

/// The validium inputs for the chunk witness.
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
pub struct ValidiumInputs {
    /// The validium transactions for each block in the chunk.
    pub validium_txs: Vec<Vec<QueueTransaction>>,
    /// The secret key used for decrypting validium transactions.
    pub secret_key: Box<[u8]>,
}

#[derive(Clone, Debug)]
pub struct ChunkDetails {
    pub num_blocks: usize,
    pub num_txs: usize,
    pub total_gas_used: u64,
}

impl ChunkWitness {
    pub fn new_scroll(
        blocks: &[BlockWitness],
        prev_msg_queue_hash: B256,
        fork_name: ForkName,
    ) -> Self {
        Self::new(blocks, prev_msg_queue_hash, fork_name, None)
    }

    pub fn new_validium(
        blocks: &[BlockWitness],
        prev_msg_queue_hash: B256,
        fork_name: ForkName,
        validium_txs: Vec<Vec<QueueTransaction>>,
        secret_key: SecretKey,
    ) -> Self {
        Self::new(
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
        blocks: &[BlockWitness],
        prev_msg_queue_hash: B256,
        fork_name: ForkName,
        validium: Option<ValidiumInputs>,
    ) -> Self {
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
            validium,
        }
    }

    /// Convert the `ChunkWitness` into a `ChunkWitnessFeynman`.
    pub fn into_feynman(self) -> ChunkWitnessFeynman {
        ChunkWitnessFeynman {
            blocks: self.blocks,
            prev_msg_queue_hash: self.prev_msg_queue_hash,
            fork_name: self.fork_name,
            compression_ratios: self.compression_ratios,
            state_commit_mode: self.state_commit_mode,
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
        // FIXME: Validium compatibility
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
        // if guest_version >= ForkName::Feynman {
        //     // Use the new rkyv serialization for Feynman and later forks
        //     rkyv::to_bytes::<rkyv::rancor::Error>(self)
        // } else {
        //     // Use the old rkyv serialization for earlier forks
        //     rkyv::to_bytes::<rkyv::rancor::Error>(&self.clone().into_euclid())
        // }
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

pub trait ChunkWitnessExt {
    fn legacy_data_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256>;

    fn rolling_msg_queue_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256>;
}

impl ChunkWitnessExt for ArchivedChunkWitness {
    #[inline]
    fn legacy_data_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256> {
        (self.fork_name < ArchivedForkName::EuclidV2).then(|| blocks.legacy_data_hash())
    }

    #[inline]
    fn rolling_msg_queue_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256> {
        if self.fork_name < ArchivedForkName::EuclidV2 {
            return None;
        }

        let prev_msg_queue_hash: B256 = self.prev_msg_queue_hash.into();

        let rolling_msg_queue_hash = match self.validium.as_ref() {
            None => blocks.rolling_msg_queue_hash(
                prev_msg_queue_hash,
                iter::repeat_n(None::<(Vec<TxL1Message>, &SecretKey)>, blocks.len()),
            ),
            Some(validium) => {
                let secret_key =
                    SecretKey::try_from_bytes(validium.secret_key.as_ref()).expect("invalid secret key");
                blocks.rolling_msg_queue_hash(
                    prev_msg_queue_hash,
                    validium
                        .validium_txs
                        .iter()
                        .map(|txs| Some((txs.iter().map(|tx| tx.into()), &secret_key))),
                )
            }
        };

        Some(rolling_msg_queue_hash)
    }
}
