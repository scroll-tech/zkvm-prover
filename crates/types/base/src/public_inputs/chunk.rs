use crate::{
    public_inputs::{ForkName, MultiVersionPublicInputs},
    utils::keccak256,
};
use alloy_primitives::{B256, U256};
use sbv_primitives::types::{
    consensus::BlockHeader,
    eips::Encodable2718,
    reth::primitives::{Block, RecoveredBlock, SignedTransaction, TransactionSigned},
};
use std::ops::Deref;
use tiny_keccak::{Hasher, Keccak};

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

impl From<&RecoveredBlock<Block>> for BlockContextV2 {
    fn from(block: &RecoveredBlock<Block>) -> BlockContextV2 {
        BlockContextV2 {
            timestamp: block.timestamp,
            gas_limit: block.gas_limit,
            base_fee: U256::from(block.base_fee_per_gas().expect("base_fee_expected")),
            num_txs: u16::try_from(block.body().transactions.len()).expect("num txs u16"),
            num_l1_msgs: u16::try_from(
                block
                    .body()
                    .transactions
                    .iter()
                    .filter(|tx| tx.is_l1_message())
                    .count(),
            )
            .expect("num l1 msgs u16"),
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
pub struct ChunkInfo {
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
}

impl From<&ArchivedChunkInfo> for ChunkInfo {
    fn from(archived: &ArchivedChunkInfo) -> Self {
        Self {
            chain_id: archived.chain_id.into(),
            prev_state_root: archived.prev_state_root.into(),
            post_state_root: archived.post_state_root.into(),
            withdraw_root: archived.withdraw_root.into(),
            data_hash: archived.data_hash.into(),
            tx_data_digest: archived.tx_data_digest.into(),
            prev_msg_queue_hash: archived.prev_msg_queue_hash.into(),
            post_msg_queue_hash: archived.post_msg_queue_hash.into(),
            tx_data_length: archived.tx_data_length.into(),
            initial_block_number: archived.initial_block_number.into(),
            block_ctxs: archived
                .block_ctxs
                .iter()
                .map(BlockContextV2::from)
                .collect(),
        }
    }
}

pub type VersionedChunkInfo = (ChunkInfo, ForkName);

impl MultiVersionPublicInputs for ChunkInfo {
    /// Compute the public input hash for the chunk.
    fn pi_hash_by_fork(&self, fork_name: ForkName) -> B256 {
        match fork_name {
            ForkName::EuclidV1 => {
                assert_ne!(self.data_hash, B256::ZERO, "v6 must has valid data hash");
                self.pi_hash_euclidv1()
            }
            ForkName::EuclidV2 => self.pi_hash_euclidv2(),
            ForkName::Feynman => {
                // Feynman fork uses the same hash as EuclidV2
                self.pi_hash_euclidv2()
            }
        }
    }

    /// Validate public inputs between 2 contiguous chunks.
    ///
    /// - chain id MUST match
    /// - state roots MUST be chained
    /// - L1 msg queue hash MUST be chained
    fn validate(&self, prev_pi: &Self, fork_name: ForkName) {
        assert_eq!(self.chain_id, prev_pi.chain_id);
        assert_eq!(self.prev_state_root, prev_pi.post_state_root);
        assert_eq!(self.prev_msg_queue_hash, prev_pi.post_msg_queue_hash);

        // message queue hash is used only after euclidv2 (da-codec@v7)
        if fork_name == ForkName::EuclidV1 {
            assert_eq!(self.prev_msg_queue_hash, B256::ZERO);
            assert_eq!(prev_pi.prev_msg_queue_hash, B256::ZERO);
            assert_eq!(self.post_msg_queue_hash, B256::ZERO);
            assert_eq!(prev_pi.post_msg_queue_hash, B256::ZERO);
        }
    }
}

pub trait ChunkExt {
    /// Hash the transaction bytes.
    ///
    /// Only L2 transactions are considered while computing the digest.
    fn tx_bytes_hash_in(&self, rlp_buffer: &mut Vec<u8>) -> (usize, B256);
    /// Data hash before Euclid V2
    fn legacy_data_hash(&self) -> B256;
    /// Rolling message queue hash after Euclid V2
    fn rolling_msg_queue_hash(&self, rolling_hash: B256) -> B256;
}

impl<T: Deref<Target = [RecoveredBlock<Block>]>> ChunkExt for T {
    #[inline]
    fn tx_bytes_hash_in(&self, rlp_buffer: &mut Vec<u8>) -> (usize, B256) {
        let blocks = self.as_ref();
        blocks
            .iter()
            .flat_map(|b| b.body().transactions.iter())
            .tx_bytes_hash_in(rlp_buffer.as_mut())
    }

    #[inline]
    fn legacy_data_hash(&self) -> B256 {
        let blocks = self.as_ref();

        let mut data_hasher = Keccak::v256();
        for block in blocks.iter() {
            block.legacy_hash_da_header(&mut data_hasher);
        }
        for block in blocks.iter() {
            block.legacy_hash_l1_msg(&mut data_hasher);
        }
        let mut data_hash = B256::ZERO;
        data_hasher.finalize(&mut data_hash.0);
        data_hash
    }

    #[inline]
    fn rolling_msg_queue_hash(&self, mut rolling_hash: B256) -> B256 {
        let blocks = self.as_ref();
        for block in blocks.iter() {
            rolling_hash = block.hash_msg_queue(&rolling_hash);
        }
        rolling_hash
    }
}

/// Helper trait for hashing transaction bytes.
trait TxBytesHashExt {
    /// Hash the transaction bytes.
    ///
    /// Only L2 transactions are considered while computing the digest.
    fn tx_bytes_hash_in(self, rlp_buffer: &mut Vec<u8>) -> (usize, B256);
}

impl<'a, I: IntoIterator<Item = &'a TransactionSigned>> TxBytesHashExt for I
where
    I: IntoIterator<Item = &'a TransactionSigned>,
{
    #[inline]
    fn tx_bytes_hash_in(self, rlp_buffer: &mut Vec<u8>) -> (usize, B256) {
        use tiny_keccak::{Hasher, Keccak};

        let mut tx_bytes_hasher = Keccak::v256();
        let mut len = 0;

        // Ignore L1 msg txs.
        for tx in self.into_iter().filter(|&tx| !tx.is_l1_message()) {
            tx.encode_2718(rlp_buffer);
            len += rlp_buffer.len();
            tx_bytes_hasher.update(rlp_buffer);
            rlp_buffer.clear();
        }

        let mut tx_bytes_hash = B256::ZERO;
        tx_bytes_hasher.finalize(&mut tx_bytes_hash.0);
        (len, tx_bytes_hash)
    }
}

/// Chunk related extension methods for Block
trait BlockChunkExt {
    /// Hash the header of the block
    fn legacy_hash_da_header(&self, hasher: &mut impl tiny_keccak::Hasher);
    /// Hash the l1 messages of the block
    fn legacy_hash_l1_msg(&self, hasher: &mut impl Hasher);
    /// Hash the l1 messages of the block
    fn hash_msg_queue(&self, initial_queue_hash: &B256) -> B256;
}

impl BlockChunkExt for RecoveredBlock<Block> {
    #[inline]
    fn legacy_hash_da_header(&self, hasher: &mut impl Hasher) {
        hasher.update(&self.number.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(
            &U256::from_limbs([self.base_fee_per_gas.unwrap_or_default(), 0, 0, 0])
                .to_be_bytes::<{ U256::BYTES }>(),
        );
        hasher.update(&self.gas_limit.to_be_bytes());
        // FIXME: l1 tx could be skipped, the actual tx count needs to be calculated
        hasher.update(&(self.body().transactions.len() as u16).to_be_bytes());
    }

    #[inline]
    fn legacy_hash_l1_msg(&self, hasher: &mut impl Hasher) {
        for tx in self
            .body()
            .transactions
            .iter()
            .filter(|tx| tx.is_l1_message())
        {
            hasher.update(tx.tx_hash().as_slice())
        }
    }

    #[inline]
    fn hash_msg_queue(&self, initial_queue_hash: &B256) -> B256 {
        let mut rolling_hash = *initial_queue_hash;
        for tx in self
            .body()
            .transactions
            .iter()
            .filter(|tx| tx.is_l1_message())
        {
            let mut hasher = Keccak::v256();
            hasher.update(rolling_hash.as_slice());
            hasher.update(tx.tx_hash().as_slice());

            hasher.finalize(rolling_hash.as_mut_slice());

            // clear last 32 bits, i.e. 4 bytes.
            // https://github.com/scroll-tech/da-codec/blob/26dc8d575244560611548fada6a3a2745c60fe83/encoding/da.go#L817-L825
            // see also https://github.com/scroll-tech/da-codec/pull/42
            rolling_hash.0[28] = 0;
            rolling_hash.0[29] = 0;
            rolling_hash.0[30] = 0;
            rolling_hash.0[31] = 0;
        }

        rolling_hash
    }
}
