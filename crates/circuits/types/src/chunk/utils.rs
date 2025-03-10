use sbv::{
    kv::nohash::NoHashMap,
    primitives::{B256, BlockWitness, Bytes, ext::BlockWitnessExt},
    trie::{BlockWitnessTrieExt, TrieNode},
};

type CodeDb = NoHashMap<B256, Bytes>;

type NodesProvider = NoHashMap<B256, TrieNode>;

type BlockHashProvider = sbv::kv::null::NullProvider;

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
    let block_hashes = sbv::kv::null::NullProvider;

    (code_db, nodes_provider, block_hashes)
}
