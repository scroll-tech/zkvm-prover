use std::convert::Infallible;
use openvm::init;
use scroll_zkvm_types_chunk::ArchivedChunkWitness;
use scroll_zkvm_types_circuit::{
    Circuit,
    io::read_witnesses,
    public_inputs::chunk::{ChunkInfo, VersionedChunkInfo},
};

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm::platform as openvm_platform,
    openvm_algebra_guest::IntMod,
    openvm_bigint_guest, // trigger extern u256 (this may be unneeded)
    openvm_k256::Secp256k1Point,
    openvm_keccak256_guest, // trigger extern native-keccak256
    openvm_p256::P256Point,
    openvm_pairing::bn254::Bn254G1Affine,
};

init!();

pub struct ChunkCircuit;

impl Circuit for ChunkCircuit {
    type Witness = ArchivedChunkWitness;
    type PublicInputs = VersionedChunkInfo;

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> &Self::Witness {
        rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(witness_bytes)
            .expect("ChunkCircuit: rkyv deserialisation of witness bytes failed")
    }

    fn validate(witness: &Self::Witness) -> Self::PublicInputs {
        (
            ChunkInfo::try_from(witness).expect("failed to execute chunk"),
            rkyv::deserialize::<_, Infallible>(&witness.fork_name).unwrap(),
        )
    }
}
