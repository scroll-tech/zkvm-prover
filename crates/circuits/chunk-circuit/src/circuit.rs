use openvm::init;
use scroll_zkvm_types_chunk::scroll::ChunkWitness;
use scroll_zkvm_types_circuit::{
    Circuit,
    io::read_witnesses,
    public_inputs::{
        Version,
        scroll::chunk::{ChunkInfo, VersionedChunkInfo},
    },
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
    type Witness = ChunkWitness;
    type PublicInputs = VersionedChunkInfo;

    fn read_witness_bytes() -> Vec<u8> {
        read_witnesses()
    }

    fn deserialize_witness(witness_bytes: &[u8]) -> Self::Witness {
        let config = bincode::config::standard();
        let (witness, _): (Self::Witness, _) =
            bincode::serde::decode_from_slice(witness_bytes, config)
                .expect("ChunkCircuit: deserialisation of witness bytes failed");
        witness
    }

    fn validate(witness: Self::Witness) -> Self::PublicInputs {
        let version = Version::from(witness.version);
        assert_eq!(version.fork, witness.fork_name);

        let chunk_info = ChunkInfo::try_from(witness).expect("failed to execute chunk");
        (chunk_info, version)
    }
}
