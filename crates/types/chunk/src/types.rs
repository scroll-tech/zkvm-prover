use std::ops::Deref;

use sbv_primitives::{
    B256, U256,
    types::{
        eips::Encodable2718,
        reth::primitives::{Block, RecoveredBlock, SignedTransaction, TransactionSigned},
    },
};

// FIXME as alloy-primitive
use tiny_keccak::{Hasher, Keccak};

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
