use crate::proof::StarkProof;
use serde::{Deserialize, Serialize};

/// Universal task for zkvm-prover, with encoded bytes which can be used
/// as stdin inputs for the app and id data for distinguish
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvingTask {
    /// seralized witness which should be written into stdin first
    pub serialized_witness: Vec<Vec<u8>>,
    /// aggregated proof carried by babybear fields, should be written into stdin
    /// followed `serialized_witness`
    pub aggregated_proofs: Vec<StarkProof>,
    /// Fork name specify
    pub fork_name: String,
    /// The vk of app which is expcted to prove this task
    pub vk: Vec<u8>,
    /// An identifier assigned by coordinator, it should be kept identify for the
    /// same task (for example, using chunk, batch and bundle hashes)
    pub identifier: String,
}
