use std::ops::Deref;

use crate::types::validium::SecretKey;
use crate::witness::ValidiumInputs;
use crate::{ChunkWitness, QueueTransaction};
use alloy_primitives::keccak256;
use itertools::Itertools;
use sbv_helpers::manually_drop_on_zkvm;
use sbv_primitives::types::consensus::TxL1Message;
use sbv_primitives::{
    B256, U256,
    types::{
        eips::Encodable2718,
        reth::primitives::{Block, RecoveredBlock, TransactionSigned},
    },
};
use types_base::fork_name::ForkName;

pub mod validium;

const LEGACY_DA_HEADER_LEN: usize = size_of::<u64>() // block number
        + size_of::<u64>() // timestamp
        + U256::BYTES // base fee per gas
        + size_of::<u64>() // gas limit
        + size_of::<u16>(); // l1 tx count

pub trait ChunkExt {
    /// Hash the transaction bytes.
    ///
    /// Only L2 transactions are considered while computing the digest.
    fn tx_bytes_hash_in(&self, rlp_buffer: &mut Vec<u8>) -> (usize, B256);
    /// Data hash before Euclid V2
    fn legacy_data_hash(&self) -> B256;
    /// Rolling message queue hash after Euclid V2
    fn rolling_msg_queue_hash(
        &self,
        rolling_hash: B256,
        validium_inputs: Option<&ValidiumInputs>,
    ) -> B256;
}

impl<T: Deref<Target = [RecoveredBlock<Block>]>> ChunkExt for T {
    #[inline]
    fn tx_bytes_hash_in(&self, rlp_buffer: &mut Vec<u8>) -> (usize, B256) {
        let blocks = self.as_ref();
        blocks
            .iter()
            .flat_map(|b| b.body().transactions.iter())
            .tx_bytes_hash_in(rlp_buffer)
    }

    #[inline]
    fn legacy_data_hash(&self) -> B256 {
        let blocks = self.as_ref();

        let num_l1_txs: usize = blocks
            .iter()
            .map(|b| {
                b.body()
                    .transactions
                    .iter()
                    .filter(|tx| tx.is_l1_message())
                    .count()
            })
            .sum();

        let mut buffer = manually_drop_on_zkvm!(Vec::with_capacity(
            blocks.len() * LEGACY_DA_HEADER_LEN + num_l1_txs * size_of::<B256>(),
        ));

        for block in blocks.iter() {
            block.encode_legacy_da_header(&mut buffer);
        }
        for block in blocks.iter() {
            block.encode_legacy_l1_msg(&mut buffer);
        }
        keccak256(&*buffer)
    }

    #[inline]
    fn rolling_msg_queue_hash(
        &self,
        mut rolling_hash: B256,
        validium_inputs: Option<&ValidiumInputs>,
    ) -> B256 {
        let blocks = self.as_ref();

        if let Some(ValidiumInputs {
            validium_txs,
            secret_key,
        }) = validium_inputs
        {
            let secret_key = SecretKey::try_from_bytes(secret_key).expect("valid secret key");

            for (block, validium_txs) in blocks.iter().zip(validium_txs.iter()) {
                rolling_hash = block
                    .hash_msg_queue(&rolling_hash, Some((validium_txs.as_slice(), &secret_key)));
            }
        } else {
            for block in blocks.iter() {
                rolling_hash = block.hash_msg_queue(&rolling_hash, None);
            }
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

impl<'a, I: Iterator<Item = &'a TransactionSigned>> TxBytesHashExt for I {
    #[inline]
    fn tx_bytes_hash_in(self, rlp_buffer: &mut Vec<u8>) -> (usize, B256) {
        rlp_buffer.clear();
        // Ignore L1 msg txs.
        for tx in self.filter(|&tx| !tx.is_l1_message()) {
            tx.encode_2718(rlp_buffer);
        }
        let hash = keccak256(&rlp_buffer);
        rlp_buffer.clear();
        (rlp_buffer.len(), hash)
    }
}

/// Chunk related extension methods for Block
trait BlockChunkExt {
    /// Get an iterator over L1 message transactions in the block.
    fn l1_txs_iter(&self) -> impl Iterator<Item = &TxL1Message>;

    /// Hash the header of the block
    fn encode_legacy_da_header(&self, buffer: &mut Vec<u8>);
    /// Hash the l1 messages of the block
    fn encode_legacy_l1_msg(&self, buffer: &mut Vec<u8>);
    /// Hash the l1 messages of the block
    fn hash_msg_queue(
        &self,
        initial_queue_hash: &B256,
        validium_txs: Option<(&[QueueTransaction], &SecretKey)>,
    ) -> B256;
}

impl BlockChunkExt for RecoveredBlock<Block> {
    #[inline]
    fn l1_txs_iter(&self) -> impl Iterator<Item = &TxL1Message> {
        self.body()
            .transactions
            .iter()
            .filter_map(|tx| tx.as_l1_message())
            .map(|tx| tx.inner())
    }

    #[inline]
    fn encode_legacy_da_header(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.number.to_be_bytes());
        buffer.extend_from_slice(&self.timestamp.to_be_bytes());
        buffer.extend_from_slice(
            &U256::from_limbs([self.base_fee_per_gas.unwrap_or_default(), 0, 0, 0])
                .to_be_bytes::<{ U256::BYTES }>(),
        );
        buffer.extend_from_slice(&self.gas_limit.to_be_bytes());
        // FIXME: l1 tx could be skipped, the actual tx count needs to be calculated
        buffer.extend_from_slice(&(self.body().transactions.len() as u16).to_be_bytes());
    }

    #[inline]
    fn encode_legacy_l1_msg(&self, buffer: &mut Vec<u8>) {
        for tx in self
            .body()
            .transactions
            .iter()
            .filter_map(|tx| tx.as_l1_message())
        {
            buffer.extend_from_slice(tx.hash_ref().as_ref());
        }
    }

    #[inline]
    fn hash_msg_queue(
        &self,
        initial_queue_hash: &B256,
        validium_txs: Option<(&[QueueTransaction], &SecretKey)>,
    ) -> B256 {
        let mut rolling_hash = *initial_queue_hash;

        let mut buffer = [0u8; { size_of::<B256>() * 2 }];
        buffer[..32].copy_from_slice(rolling_hash.as_ref());

        let mut hash_tx = |tx_hash: B256| {
            buffer[..size_of::<B256>()].copy_from_slice(rolling_hash.as_ref());
            buffer[size_of::<B256>()..].copy_from_slice(tx_hash.as_ref());

            rolling_hash = keccak256(&buffer);
            // clear last 32 bits, i.e. 4 bytes.
            // https://github.com/scroll-tech/da-codec/blob/26dc8d575244560611548fada6a3a2745c60fe83/encoding/da.go#L817-L825
            // see also https://github.com/scroll-tech/da-codec/pull/42
            rolling_hash.0[28] = 0;
            rolling_hash.0[29] = 0;
            rolling_hash.0[30] = 0;
            rolling_hash.0[31] = 0;
        };

        if let Some((txs, secret_key)) = validium_txs {
            for (validium_tx, tx_in_block) in txs.iter().zip_eq(self.l1_txs_iter()) {
                let validium_tx = TxL1Message::from(validium_tx);
                match validium::decrypt(&validium_tx, secret_key) {
                    Ok(decrypted) => {
                        assert_eq!(decrypted, *tx_in_block);
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                    }
                }

                hash_tx(validium_tx.tx_hash());
            }
        } else {
            for tx in self.l1_txs_iter() {
                hash_tx(tx.tx_hash());
            }
        };

        rolling_hash
    }
}

pub trait ChunkWitnessExt {
    fn legacy_data_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256>;

    fn rolling_msg_queue_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256>;
}

impl ChunkWitnessExt for ChunkWitness {
    #[inline]
    fn legacy_data_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256> {
        (self.fork_name < ForkName::EuclidV2).then(|| blocks.legacy_data_hash())
    }

    #[inline]
    fn rolling_msg_queue_hash(&self, blocks: &[RecoveredBlock<Block>]) -> Option<B256> {
        (self.fork_name < ForkName::EuclidV2).then(|| {
            blocks.rolling_msg_queue_hash(self.prev_msg_queue_hash, self.validium.as_ref())
        })
    }
}
