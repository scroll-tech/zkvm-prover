use openvm_native_recursion::hints::Hintable;
use openvm_sdk::verifier::root::types::RootVmVerifierInput;
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::BabyBearPoseidon2Config,
    openvm_stark_backend::p3_field::PrimeField32,
};
use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeader, BatchHeaderV3, BatchWitness, ReferenceHeader},
    proof::FlattenedRootProof,
};
use serde::{Deserialize, Serialize};

use crate::{ChunkProof, task::ProvingTask, utils::base64};

/// Defines a proving task for batch proof generation.
#[derive(Clone, Deserialize, Serialize)]
pub struct BatchProvingTask {
    /// Chunk proofs for the contiguous list of chunks within the batch.
    pub chunk_proofs: Vec<ChunkProof>,
    /// The [`BatchHeaderV3`], as computed on-chain for this batch.
    ///
    /// Ref: https://github.com/scroll-tech/scroll-contracts/blob/2ac4f3f7e090d7127db4b13b3627cb3ce2d762bc/src/libraries/codec/BatchHeaderV3Codec.sol
    pub batch_header: BatchHeaderV3,
    /// The bytes encoding the batch data that will finally be published on-chain in the form of an
    /// EIP-4844 blob.
    #[serde(with = "base64")]
    pub blob_bytes: Vec<u8>,
}

impl ProvingTask for BatchProvingTask {
    fn identifier(&self) -> String {
        self.batch_header.batch_hash().to_string()
    }

    fn to_witness_serialized(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        let witness = BatchWitness {
            chunk_proofs: self
                .chunk_proofs
                .iter()
                .map(|p| flatten_root_proof(&p.proof))
                .collect(),
            chunk_infos: self
                .chunk_proofs
                .iter()
                .map(|p| p.metadata.chunk_info.clone())
                .collect(),
            blob_bytes: self.blob_bytes.clone(),
            reference_header: ReferenceHeader::V3(self.batch_header),
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&witness)
    }
}

fn flatten_root_proof(
    root_proof: &RootVmVerifierInput<BabyBearPoseidon2Config>,
) -> FlattenedRootProof {
    let full_proof_steams = root_proof.write();

    let mut flatten_input: Vec<u32> = Vec::new();
    for x in &full_proof_steams {
        flatten_input.push(x.len() as u32);
        for f in x {
            flatten_input.push(f.as_canonical_u32());
        }
    }
    let mut public_values = vec![];
    public_values.extend(
        root_proof
            .public_values
            .iter()
            .map(|x| x.as_canonical_u32()),
    );
    FlattenedRootProof {
        flatten_proof: flatten_input,
        public_values,
    }
}
