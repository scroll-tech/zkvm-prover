use crate::chunk::BlockContextV2;
use sbv::{
    kv::nohash::NoHashMap,
    primitives::{
        B256, BlockWitness, Bytes, RecoveredBlock, U256, alloy_consensus::BlockHeader,
        ext::BlockWitnessExt, types::reth::Block,
    },
    trie::{BlockWitnessTrieExt, TrieNode},
};

type CodeDb = NoHashMap<B256, Bytes>;

type NodesProvider = NoHashMap<B256, TrieNode>;

#[cfg(feature = "scroll")]
type BlockHashProvider = sbv::kv::null::NullProvider;

#[cfg(not(feature = "scroll"))]
type BlockHashProvider = NoHashMap<u64, B256>;

pub fn make_providers<W: BlockWitness>(
    witnesses: &[W],
) -> (CodeDb, NodesProvider, BlockHashProvider) {
    let code_db = {
        // build code db
        let num_codes = witnesses.iter().map(|w| w.codes_iter().len()).sum();
        let mut code_db =
            NoHashMap::<B256, Bytes>::with_capacity_and_hasher(num_codes, Default::default());
        witnesses.import_codes(&mut code_db);
        code_db
    };
    let nodes_provider = {
        let num_states = witnesses.iter().map(|w| w.states_iter().len()).sum();
        let mut nodes_provider =
            NoHashMap::<B256, TrieNode>::with_capacity_and_hasher(num_states, Default::default());
        witnesses.import_nodes(&mut nodes_provider).unwrap();
        nodes_provider
    };
    #[cfg(not(feature = "scroll"))]
    let block_hashes = {
        let num_hashes = witnesses.iter().map(|w| w.block_hashes_iter().len()).sum();
        let mut block_hashes =
            NoHashMap::<u64, B256>::with_capacity_and_hasher(num_hashes, Default::default());
        witnesses.import_block_hashes(&mut block_hashes);
        block_hashes
    };
    #[cfg(feature = "scroll")]
    let block_hashes = sbv::kv::null::NullProvider;

    (code_db, nodes_provider, block_hashes)
}

impl From<&RecoveredBlock<Block>> for BlockContextV2 {
    fn from(value: &RecoveredBlock<Block>) -> Self {
        Self {
            timestamp: value.timestamp,
            gas_limit: value.gas_limit,
            base_fee: U256::from(value.base_fee_per_gas().expect("base_fee_expected")),
            num_txs: u16::try_from(value.body().transactions.len()).expect("num txs u16"),
            num_l1_msgs: u16::try_from(
                value
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
