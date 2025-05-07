use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::chunk::{ArchivedChunkWitness, ChunkWitness, execute};
use serde::Serialize;
use serde_json::json;
use std::{str::FromStr, sync::LazyLock};

use crate::{
    Error, Prover, ProverType,
    commitments::{chunk, chunk_rv32},
    proof::{ChunkProofMetadata, RootProof},
    task::{ProvingTask, chunk::ChunkProvingTask},
};

use super::Commitments;

pub struct ChunkCircuit;
pub struct ChunkCircuitRv32;

impl Commitments for ChunkCircuit {
    const EXE_COMMIT: [u32; 8] = chunk::EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = chunk::LEAF_COMMIT;
}

impl Commitments for ChunkCircuitRv32 {
    const EXE_COMMIT: [u32; 8] = chunk_rv32::EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = chunk_rv32::LEAF_COMMIT;
}

pub type ChunkProverType = GenericChunkProverType<ChunkCircuit>;
pub type ChunkProverTypeRv32 = GenericChunkProverType<ChunkCircuitRv32>;

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;
#[allow(dead_code)]
pub type ChunkProverRv32 = Prover<ChunkProverTypeRv32>;

pub struct GenericChunkProverType<C: Commitments>(std::marker::PhantomData<C>);

impl<C: Commitments> ProverType for GenericChunkProverType<C> {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    const SEGMENT_SIZE: usize = (1 << 22) - 100;

    const EXE_COMMIT: [u32; 8] = C::EXE_COMMIT;

    const LEAF_COMMIT: [u32; 8] = C::LEAF_COMMIT;

    type ProvingTask = ChunkProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = ChunkProofMetadata;

    fn metadata_with_prechecks(task: &mut Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let err_prefix = format!(
            "metadata_with_prechecks for task_id={:?}",
            task.identifier()
        );

        if task.block_witnesses.is_empty() {
            return Err(Error::GenProof(format!(
                "{err_prefix}: chunk should contain at least one block",
            )));
        }

        let fork_name = task.fork_name.as_str().into();

        let chunk_info = loop {
            match execute(&task.block_witnesses, task.prev_msg_queue_hash, fork_name) {
                Ok(chunk_info) => break chunk_info,
                Err(e) => {
                    if let Some(hash) = e.as_blinded_node_err() {
                        let node = fetch_missing_node(hash).map_err(|e| {
                            Error::GenProof(format!(
                                "{err_prefix}: failed to fetch missing node: {e}",
                            ))
                        })?;
                        task.block_witnesses[0].states.push(node)
                    } else {
                        return Err(Error::GenProof(format!("{}: {}", err_prefix, e)));
                    }
                }
            }
        };

        // rkyv check
        {
            let chunk_witness =
                ChunkWitness::new(&task.block_witnesses, task.prev_msg_queue_hash, fork_name);
            let serialized =
                rkyv::to_bytes::<rkyv::rancor::Error>(&chunk_witness).map_err(|e| {
                    Error::GenProof(format!(
                        "{}: failed to serialize chunk witness: {}",
                        err_prefix, e
                    ))
                })?;
            let _chunk_witness =
                rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(&serialized)
                    .map_err(|e| {
                        Error::GenProof(format!(
                            "{}: rkyv deserialisation of chunk witness bytes failed: {}",
                            err_prefix, e
                        ))
                    })?;
        }

        Ok(ChunkProofMetadata { chunk_info })
    }
}

#[tracing::instrument]
fn fetch_missing_node(hash: B256) -> Result<sbv_primitives::Bytes, String> {
    const MAX_RETRIES: usize = 3;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "debug_dbGet",
        "params": [hash],
    });
    tracing::debug!("request_body: {body:?}");

    let mut retries = 0;
    loop {
        match fetch_missing_node_inner(&body) {
            Ok(res) => {
                // 1. success: {"jsonrpc":"2.0","id":1,"result":"0xe19f3c8dfeea98e16e7fcafcce43929240f3ff23ad27fc7a81d5368b0e9eb6876a32"}
                // 2. method not supported: {"jsonrpc":"2.0","id":1,"error":{"code":-32604,"message":"this request method is not supported"}}
                // 3. node not found: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"leveldb: not found"}}
                if let Some(error) = res.get("error") {
                    let message = error
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    return Err(format!("error from RPC: {message}"));
                }
                if let Some(node) = res.get("result").and_then(|v| v.as_str()) {
                    return sbv_primitives::Bytes::from_str(node).map_err(|e| {
                        tracing::error!("failed to parse hex: {e}");
                        format!("failed to parse hex: {e}")
                    });
                }
                return Err(format!("invalid response: {res:?}"));
            }
            Err(e) => {
                tracing::debug!("retry#{retries}, error: {e:?}");
                retries += 1;
                if retries > MAX_RETRIES {
                    tracing::error!("max retries reached, last err: {e}");
                    return Err(format!("failed after {MAX_RETRIES} retries, last err: {e}"));
                }
                continue;
            }
        }
    }
}

fn fetch_missing_node_inner<T: Serialize + ?Sized>(body: &T) -> reqwest::Result<serde_json::Value> {
    static RPC_ENDPOINT: LazyLock<String> = LazyLock::new(|| {
        std::env::var("RPC_ENDPOINT")
            .as_deref()
            .unwrap_or("http://localhost:8545")
            .trim_end_matches("/")
            .to_string()
    });

    static CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
        reqwest::blocking::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create reqwest client")
    });

    CLIENT
        .post(RPC_ENDPOINT.as_str())
        .json(body)
        .send()?
        .error_for_status()?
        .json()
}
