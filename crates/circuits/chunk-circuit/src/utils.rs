use rkyv::{rancor, vec::ArchivedVec};
use sbv::{
    kv::nohash::NoHashMap,
    primitives::{B256, BlockWitness, Bytes, ext::BlockWitnessExt, types::ArchivedBlockWitness},
    trie::{BlockWitnessTrieExt, TrieNode},
};

#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm::platform as openvm_platform;

// Read the witnesses from the hint stream.
// rkyv needs special alignment for its data structures, use a pre-aligned
// buffer with rkyv::access_unchecked is more efficient than rkyv::access
#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn read_witnesses() -> Vec<u8> {
    use std::alloc::{GlobalAlloc, Layout, System};
    openvm_rv32im_guest::hint_input();
    let mut len: u32 = 0;
    openvm_rv32im_guest::hint_store_u32!((&mut len) as *mut u32 as u32);
    let num_words = (len + 3) / 4;
    let size = (num_words * 4) as usize;
    let layout = Layout::from_size_align(size, 16).unwrap();
    let ptr_start = unsafe { System.alloc(layout) };
    let mut ptr = ptr_start;
    for _ in 0..num_words {
        openvm_rv32im_guest::hint_store_u32!(ptr as u32);
        ptr = unsafe { ptr.add(4) };
    }
    unsafe { Vec::from_raw_parts(ptr_start, len as usize, size) }
}

// dummy implement to avoid complains
#[cfg(not(target_os = "zkvm"))]
pub fn read_witnesses() -> Vec<u8> {
    openvm::io::read_vec()
}

/// Deserialize serialized bytes into archived witness for the chunk circuit.
#[inline(always)]
pub fn deserialize_witness(serialized: &[u8]) -> &ArchivedVec<ArchivedBlockWitness> {
    rkyv::access::<ArchivedVec<ArchivedBlockWitness>, rancor::BoxedError>(serialized).unwrap()
}

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
