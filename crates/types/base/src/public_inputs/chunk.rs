use crate::{
    public_inputs::{ForkName, MultiVersionPublicInputs},
    utils::keccak256,
    version::{Domain, STFVersion, Version},
};
use alloy_primitives::{B256, U256};

/// Number of bytes used to serialise [`BlockContextV2`].
pub const SIZE_BLOCK_CTX: usize = 52;

/// Represents the version 2 of block context.
///
/// The difference between v2 and v1 is that the block number field has been removed since v2.
#[derive(
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct BlockContextV2 {
    /// The timestamp of the block.
    pub timestamp: u64,
    /// The base fee of the block.
    pub base_fee: U256,
    /// The gas limit of the block.
    pub gas_limit: u64,
    /// The number of transactions in the block, including both L1 msg txs as well as L2 txs.
    pub num_txs: u16,
    /// The number of L1 msg txs in the block.
    pub num_l1_msgs: u16,
}

impl From<&ArchivedBlockContextV2> for BlockContextV2 {
    fn from(archived: &ArchivedBlockContextV2) -> Self {
        Self {
            timestamp: archived.timestamp.into(),
            base_fee: archived.base_fee.into(),
            gas_limit: archived.gas_limit.into(),
            num_txs: archived.num_txs.into(),
            num_l1_msgs: archived.num_l1_msgs.into(),
        }
    }
}

impl From<&[u8]> for BlockContextV2 {
    fn from(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), SIZE_BLOCK_CTX);

        let timestamp = u64::from_be_bytes(bytes[0..8].try_into().expect("should not fail"));
        let base_fee = U256::from_be_slice(&bytes[8..40]);
        let gas_limit = u64::from_be_bytes(bytes[40..48].try_into().expect("should not fail"));
        let num_txs = u16::from_be_bytes(bytes[48..50].try_into().expect("should not fail"));
        let num_l1_msgs = u16::from_be_bytes(bytes[50..52].try_into().expect("should not fail"));

        Self {
            timestamp,
            base_fee,
            gas_limit,
            num_txs,
            num_l1_msgs,
        }
    }
}

impl BlockContextV2 {
    /// Serialize the block context in packed form.
    pub fn to_bytes(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.timestamp.to_be_bytes())
            .chain(self.base_fee.to_be_bytes::<32>())
            .chain(self.gas_limit.to_be_bytes())
            .chain(self.num_txs.to_be_bytes())
            .chain(self.num_l1_msgs.to_be_bytes())
            .collect()
    }
}

/// Represents header-like information for the chunk.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ChunkInfo {
    /// The EIP-155 chain ID for all txs in the chunk.
    pub chain_id: u64,
    /// The state root before applying the chunk.
    pub prev_state_root: B256,
    /// The state root after applying the chunk.
    pub post_state_root: B256,
    /// The withdrawals root after applying the chunk.
    pub withdraw_root: B256,
    /// Digest of L1 message txs force included in the chunk.
    /// It is a legacy field and can be omitted in new defination
    #[serde(default)]
    pub data_hash: B256,
    /// Digest of L2 tx data flattened over all L2 txs in the chunk.
    pub tx_data_digest: B256,
    /// The L1 msg queue hash at the end of the previous chunk.
    pub prev_msg_queue_hash: B256,
    /// The L1 msg queue hash at the end of the current chunk.
    pub post_msg_queue_hash: B256,
    /// The length of rlp encoded L2 tx bytes flattened over all L2 txs in the chunk.
    pub tx_data_length: u64,
    /// The block number of the first block in the chunk.
    pub initial_block_number: u64,
    /// The block contexts of the blocks in the chunk.
    pub block_ctxs: Vec<BlockContextV2>,
    /// The blockhash of the last block in the previous chunk.
    pub prev_blockhash: B256,
    /// The blockhash of the last block in the current chunk.
    pub post_blockhash: B256,
    /// Optional encryption key for encrypted L1 msgs, which is used in case of domain=Validium.
    pub encryption_key: Option<Box<[u8]>>,
}

/// Represents header-like information for the chunk.
#[derive(
    Debug,
    Clone,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct LegacyChunkInfo {
    /// The EIP-155 chain ID for all txs in the chunk.
    #[rkyv()]
    pub chain_id: u64,
    /// The state root before applying the chunk.
    #[rkyv()]
    pub prev_state_root: B256,
    /// The state root after applying the chunk.
    #[rkyv()]
    pub post_state_root: B256,
    /// The withdrawals root after applying the chunk.
    #[rkyv()]
    pub withdraw_root: B256,
    /// Digest of L1 message txs force included in the chunk.
    /// It is a legacy field and can be omitted in new defination
    #[rkyv()]
    #[serde(default)]
    pub data_hash: B256,
    /// Digest of L2 tx data flattened over all L2 txs in the chunk.
    #[rkyv()]
    pub tx_data_digest: B256,
    /// The L1 msg queue hash at the end of the previous chunk.
    #[rkyv()]
    pub prev_msg_queue_hash: B256,
    /// The L1 msg queue hash at the end of the current chunk.
    #[rkyv()]
    pub post_msg_queue_hash: B256,
    /// The length of rlp encoded L2 tx bytes flattened over all L2 txs in the chunk.
    #[rkyv()]
    pub tx_data_length: u64,
    /// The block number of the first block in the chunk.
    #[rkyv()]
    pub initial_block_number: u64,
    /// The block contexts of the blocks in the chunk.
    #[rkyv()]
    pub block_ctxs: Vec<BlockContextV2>,
}
impl std::fmt::Display for ChunkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Create a wrapper struct that implements Debug
        struct DisplayWrapper<'a>(&'a ChunkInfo);

        impl<'a> std::fmt::Debug for DisplayWrapper<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("ChunkInfo")
                    .field("chain_id", &self.0.chain_id)
                    .field("prev_state_root", &self.0.prev_state_root)
                    .field("post_state_root", &self.0.post_state_root)
                    .field("withdraw_root", &self.0.withdraw_root)
                    .field("data_hash", &self.0.data_hash)
                    .field("tx_data_digest", &self.0.tx_data_digest)
                    .field("prev_msg_queue_hash", &self.0.prev_msg_queue_hash)
                    .field("post_msg_queue_hash", &self.0.post_msg_queue_hash)
                    .field("tx_data_length", &self.0.tx_data_length)
                    .field("initial_block_number", &self.0.initial_block_number)
                    .field("prev_blockhash", &self.0.prev_blockhash)
                    .field("post_blockhash", &self.0.post_blockhash)
                    .field("block_ctxs", &"<omitted>")
                    .finish()
            }
        }

        // Use the Debug implementation with pretty formatting
        write!(f, "{:#?}", DisplayWrapper(self))
    }
}

impl From<ChunkInfo> for LegacyChunkInfo {
    fn from(value: ChunkInfo) -> Self {
        Self {
            chain_id: value.chain_id,
            prev_state_root: value.prev_state_root,
            post_state_root: value.post_state_root,
            withdraw_root: value.withdraw_root,
            data_hash: value.data_hash,
            tx_data_digest: value.tx_data_digest,
            prev_msg_queue_hash: value.prev_msg_queue_hash,
            post_msg_queue_hash: value.post_msg_queue_hash,
            tx_data_length: value.tx_data_length,
            initial_block_number: value.initial_block_number,
            block_ctxs: value.block_ctxs,
        }
    }
}

impl ChunkInfo {
    /// Public input hash for a given chunk (euclidv1 or da-codec@v6) is defined as
    ///
    /// keccak(
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     chunk data hash ||
    ///     tx data hash
    /// )
    pub fn pi_hash_euclidv1(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(&self.chain_id.to_be_bytes())
                .chain(self.prev_state_root.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.data_hash.as_slice())
                .chain(self.tx_data_digest.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    /// Public input hash for a given chunk (euclidv2 or da-codec@v7) is defined as
    ///
    /// keccak(
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     tx data digest ||
    ///     prev msg queue hash ||
    ///     post msg queue hash ||
    ///     initial block number ||
    ///     block_ctx for block_ctx in block_ctxs
    /// )
    pub fn pi_hash_euclidv2(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(&self.chain_id.to_be_bytes())
                .chain(self.prev_state_root.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.tx_data_digest.as_slice())
                .chain(self.prev_msg_queue_hash.as_slice())
                .chain(self.post_msg_queue_hash.as_slice())
                .chain(&self.initial_block_number.to_be_bytes())
                .chain(
                    self.block_ctxs
                        .iter()
                        .flat_map(|block_ctx| block_ctx.to_bytes())
                        .collect::<Vec<u8>>()
                        .as_slice(),
                )
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    /// Feynman chunk public inputs are the same as EuclidV2.
    pub fn pi_hash_feynman(&self) -> B256 {
        self.pi_hash_euclidv2()
    }

    /// Public input hash for a given chunk (galileo or da-codec@v9) is defined as
    ///
    /// keccak(
    ///     version ||
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     tx data digest ||
    ///     prev msg queue hash ||
    ///     post msg queue hash ||
    ///     initial block number ||
    ///     block_ctx for block_ctx in block_ctxs
    /// )
    pub fn pi_hash_galileo(&self, version: Version) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(&[version.as_version_byte()])
                .chain(&self.chain_id.to_be_bytes())
                .chain(self.prev_state_root.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.tx_data_digest.as_slice())
                .chain(self.prev_msg_queue_hash.as_slice())
                .chain(self.post_msg_queue_hash.as_slice())
                .chain(&self.initial_block_number.to_be_bytes())
                .chain(
                    self.block_ctxs
                        .iter()
                        .flat_map(|block_ctx| block_ctx.to_bytes())
                        .collect::<Vec<u8>>()
                        .as_slice(),
                )
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    /// Public input hash for a given chunk for L3 validium @ v1:
    ///
    /// keccak(
    ///     version ||
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     tx data digest ||
    ///     prev msg queue hash ||
    ///     post msg queue hash ||
    ///     initial block number ||
    ///     block_ctx for block_ctx in block_ctxs ||
    ///     prev blockhash ||
    ///     post blockhash ||
    ///     encryption key
    /// )
    pub fn pi_hash_validium(&self, version: Version) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(&[version.as_version_byte()])
                .chain(&self.chain_id.to_be_bytes())
                .chain(self.prev_state_root.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.tx_data_digest.as_slice())
                .chain(self.prev_msg_queue_hash.as_slice())
                .chain(self.post_msg_queue_hash.as_slice())
                .chain(&self.initial_block_number.to_be_bytes())
                .chain(
                    self.block_ctxs
                        .iter()
                        .flat_map(|block_ctx| block_ctx.to_bytes())
                        .collect::<Vec<u8>>()
                        .as_slice(),
                )
                .chain(self.prev_blockhash.as_slice())
                .chain(self.post_blockhash.as_slice())
                .chain(self.encryption_key.as_ref().expect("domain=Validium"))
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }
}

pub type VersionedChunkInfo = (ChunkInfo, Version);

impl MultiVersionPublicInputs for ChunkInfo {
    /// Compute the public input hash for the chunk given the version tuple.
    fn pi_hash_by_version(&self, version: Version) -> B256 {
        match (version.domain, version.stf_version) {
            (Domain::Scroll, STFVersion::V6) => {
                assert_ne!(self.data_hash, B256::ZERO, "v6 must have valid data_hash");
                self.pi_hash_euclidv1()
            }
            (Domain::Scroll, STFVersion::V7) => self.pi_hash_euclidv2(),
            (Domain::Scroll, STFVersion::V8) => self.pi_hash_feynman(),
            (Domain::Scroll, STFVersion::V9) => self.pi_hash_galileo(version),
            (Domain::Validium, STFVersion::V1) => self.pi_hash_validium(version),
            (domain, stf_version) => {
                unreachable!("unsupported version=({domain:?}, {stf_version:?})")
            }
        }
    }

    /// Validate public inputs between 2 contiguous chunks.
    ///
    /// - chain id MUST match
    /// - state roots MUST be chained
    /// - L1 msg queue hash MUST be chained
    ///
    /// Furthermore, for validiums we must also chain the blockhashes.
    fn validate(&self, prev_pi: &Self, version: Version) {
        assert_eq!(self.chain_id, prev_pi.chain_id);
        assert_eq!(self.prev_state_root, prev_pi.post_state_root);
        assert_eq!(self.prev_msg_queue_hash, prev_pi.post_msg_queue_hash);

        // message queue hash is used only after euclidv2 (da-codec@v7)
        if version.fork == ForkName::EuclidV1 {
            assert_eq!(self.prev_msg_queue_hash, B256::ZERO);
            assert_eq!(prev_pi.prev_msg_queue_hash, B256::ZERO);
            assert_eq!(self.post_msg_queue_hash, B256::ZERO);
            assert_eq!(prev_pi.post_msg_queue_hash, B256::ZERO);
        }

        // - blockhash chaining must be validated for validiums.
        // - encryption key must be the same between contiguous chunks in a batch.
        if version.domain == Domain::Validium {
            assert_eq!(self.prev_blockhash, prev_pi.post_blockhash);
            assert!(self.encryption_key.is_some());
            assert_eq!(self.encryption_key, prev_pi.encryption_key);
        }
    }
}
