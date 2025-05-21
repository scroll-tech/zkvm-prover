use crate::manually_drop_on_zkvm;
use sbv_kv::nohash::NoHashMap;
use sbv_primitives::{B256, BlockWitness, Bytes, ext::BlockWitnessExt};
use sbv_trie::{BlockWitnessTrieExt, TrieNode};

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub type CodeDb = NoHashMap<B256, Bytes>;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub type NodesProvider = NoHashMap<B256, TrieNode>;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub type CodeDb = std::mem::ManuallyDrop<NoHashMap<B256, Bytes>>;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub type NodesProvider = std::mem::ManuallyDrop<NoHashMap<B256, TrieNode>>;

pub fn make_providers<W: BlockWitness>(witnesses: &[W]) -> (CodeDb, NodesProvider) {
    let code_db = manually_drop_on_zkvm!({
        // build code db
        let num_codes = witnesses.iter().map(|w| w.codes_iter().len()).sum();
        let mut code_db =
            NoHashMap::<B256, Bytes>::with_capacity_and_hasher(num_codes, Default::default());
        witnesses.import_codes(&mut code_db);
        code_db
    });
    let nodes_provider = manually_drop_on_zkvm!({
        let num_states = witnesses.iter().map(|w| w.states_iter().len()).sum();
        let mut nodes_provider =
            NoHashMap::<B256, TrieNode>::with_capacity_and_hasher(num_states, Default::default());
        witnesses.import_nodes(&mut nodes_provider).unwrap();
        nodes_provider
    });

    (code_db, nodes_provider)
}
