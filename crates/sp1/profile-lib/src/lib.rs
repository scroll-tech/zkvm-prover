use sbv_kv::nohash::NoHashMap;
use sbv_primitives::{B256, Bytes, U256, types::BlockWitness};
use sbv_trie::TrieNode;
use scroll_zkvm_types_base::fork_name::ForkName;

pub type CodeDb = NoHashMap<B256, Bytes>;
pub type NodesProvider = NoHashMap<B256, TrieNode>;
pub type BlockHashProvider = sbv_kv::null::NullProvider;

#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub enum StateCommitMode {
    Chunk,
    Block,
    Auto,
}

/// The witness type accepted by the chunk-circuit.
#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
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
}
