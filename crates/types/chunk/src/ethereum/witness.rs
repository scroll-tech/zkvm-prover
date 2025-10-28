use sbv_core::BlockWitness;
use std::collections::HashSet;

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChunkWitness {
    /// The block witness for each block in the chunk.
    pub blocks: Vec<BlockWitness>,
}

#[derive(Clone, Debug)]
pub struct ChunkDetails {
    pub num_blocks: usize,
    pub num_txs: usize,
    pub total_gas_used: u64,
}

impl ChunkWitness {
    pub fn new(blocks: &[BlockWitness]) -> Self {
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
                block_hashes: block.block_hashes.clone(),
            })
            .collect();

        Self { blocks }
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
