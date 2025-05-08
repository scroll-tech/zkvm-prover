use crate::{
    Error, Prover, ProverType,
    commitments::{chunk, chunk_rv32},
    proof::{ChunkProofMetadata, RootProof},
    task::{ProvingTask, chunk::ChunkProvingTask},
};
use alloy_primitives::B256;
use scroll_zkvm_circuit_input_types::chunk::{ArchivedChunkWitness, ChunkWitness, execute};
use std::{sync::LazyLock, time::Duration};

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

static PROVER_DB_GET_ENDPOINT: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("PROVER_DB_GET_ENDPOINT")
        .as_deref()
        .ok()
        .map(|s| s.trim_end_matches("/").to_string())
});

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

        const MAX_FETCH_NODES_ATTEMPTS: usize = 100;
        let mut attempts = 0;
        let chunk_info = loop {
            let chunk_witness =
                ChunkWitness::new(&task.block_witnesses, task.prev_msg_queue_hash, fork_name);
            let serialized =
                rkyv::to_bytes::<rkyv::rancor::Error>(&chunk_witness).map_err(|e| {
                    Error::GenProof(format!(
                        "{}: failed to serialize chunk witness: {}",
                        err_prefix, e
                    ))
                })?;
            let chunk_witness =
                rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(&serialized)
                    .map_err(|e| {
                        Error::GenProof(format!(
                            "{}: rkyv deserialisation of chunk witness bytes failed: {}",
                            err_prefix, e
                        ))
                    })?;

            match execute(chunk_witness) {
                Ok(chunk_info) => break chunk_info,
                Err(e) => {
                    if let Some(hash) = e.as_blinded_node_err() {
                        if PROVER_DB_GET_ENDPOINT.is_some() {
                            let node = fetch_missing_node(hash).map_err(|e| {
                                Error::GenProof(format!(
                                    "{err_prefix}: failed to fetch missing node: {e}",
                                ))
                            })?;
                            tracing::warn!("missing node fetched: {node}");
                            task.block_witnesses[0].states.push(node);
                            attempts += 1;
                            if attempts > MAX_FETCH_NODES_ATTEMPTS {
                                return Err(Error::GenProof(format!(
                                    "{err_prefix}: max attempts reached for fetching missing nodes",
                                )));
                            }
                            continue;
                        }
                        tracing::warn!("PROVER_DB_GET_ENDPOINT not set, won't fetch missing nodes");
                    }
                    return Err(Error::GenProof(format!("{}: {}", err_prefix, e)));
                }
            }
        };

        Ok(ChunkProofMetadata { chunk_info })
    }
}

#[tracing::instrument]
fn fetch_missing_node(hash: B256) -> Result<sbv_primitives::Bytes, String> {
    use backon::{BlockingRetryableWithContext, ExponentialBuilder};

    const RETRY_POLICY: ExponentialBuilder = ExponentialBuilder::new()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(10))
        .with_max_times(3);

    static CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
        reqwest::blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create reqwest client")
    });

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "debug_dbGet",
        "params": [hash],
    });
    tracing::debug!("request_body: {body:?}");

    #[derive(serde::Deserialize)]
    enum Response {
        Result(sbv_primitives::Bytes),
        Error { code: i64, message: String },
    }

    let (_, result) = {
        |body| {
            let result = CLIENT
                .post(PROVER_DB_GET_ENDPOINT.as_ref().unwrap())
                .json(body)
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.json::<Response>());
            (body, result)
        }
    }
    .retry(RETRY_POLICY)
    .notify(|err, dur| {
        tracing::debug!("retrying {err:?} after {dur:?}");
    })
    .context(&body)
    .call();

    match result {
        // 1. success: {"jsonrpc":"2.0","id":1,"result":"0xe19f3c8dfeea98e16e7fcafcce43929240f3ff23ad27fc7a81d5368b0e9eb6876a32"}
        Ok(Response::Result(bytes)) => Ok(bytes),
        // 2. method not supported: {"jsonrpc":"2.0","id":1,"error":{"code":-32604,"message":"this request method is not supported"}}
        // 3. node not found: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"leveldb: not found"}}
        Ok(Response::Error { code, message }) => Err(format!("error from RPC: {code} {message}")),
        Err(e) => Err(format!("failed after max retries, last err: {e}")),
    }
}
