use std::path::Path;

use once_cell::sync::Lazy;
use openvm_continuations::verifier::root::types::RootVmVerifierInput;
use openvm_native_recursion::halo2::RawEvmProof;
use openvm_sdk::{
    SC, Sdk, commit::CommitBytes, config::AggStarkConfig, keygen::AggStarkProvingKey,
};
use scroll_zkvm_types::types_agg::ProgramCommitment;
use snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fn compress_commitment(commitment: &[u32; 8]) -> Fr {
    use openvm_stark_sdk::{openvm_stark_backend::p3_field::PrimeField32, p3_baby_bear::BabyBear};
    let order = Fr::from(BabyBear::ORDER_U32 as u64);
    let mut base = Fr::one();
    let mut ret = Fr::zero();

    for v in commitment {
        ret += Fr::from(*v as u64) * base;
        base *= order;
    }

    ret
}

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
pub static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()));

pub struct UniversalVerifier {
    pub evm_verifier: Vec<u8>,
}

impl UniversalVerifier {
    pub fn setup<P: AsRef<Path>>(path_verifier_code: P) -> eyre::Result<Self> {
        let evm_verifier = std::fs::read(path_verifier_code.as_ref())?;

        Ok(Self { evm_verifier })
    }

    pub fn verify_stark_proof(root_proof: &RootVmVerifierInput<SC>, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        let agg_stark_pk = &AGG_STARK_PROVING_KEY;
        let sdk = Sdk::new();

        use openvm_continuations::verifier::internal::types::VmStarkProof;
        let vm_stark_proof = VmStarkProof {
            proof: root_proof.proofs[0].clone(),
            user_public_values: root_proof.public_values.clone(),
        };
        sdk.verify_e2e_stark_proof(
            agg_stark_pk,
            &vm_stark_proof,
            &CommitBytes::from_u32_digest(&prog_commit.exe).to_bn254(),
            &CommitBytes::from_u32_digest(&prog_commit.vm).to_bn254(),
        )?;

        Ok(())
    }

    pub fn verify_evm_proof(&self, evm_proof: &RawEvmProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        if evm_proof.instances[12] != compress_commitment(&prog_commit.exe) {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.instances[13] != compress_commitment(&prog_commit.vm) {
            eyre::bail!("evm: mismatch EXE commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof)
            .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test::WrappedProof;
    use scroll_zkvm_types::proof::ProofEnum;
    use std::path::Path;

    use super::*;

    const PATH_TESTDATA: &str = "./testdata";

    impl UniversalVerifier {
        /// test method to be compatible with euclid wrapped proofs
        pub fn verify_wrapped_proof(&self, proof: &WrappedProof) -> eyre::Result<()> {
            match &proof.proof {
                ProofEnum::Evm(p) => {
                    crate::evm::verify_evm_proof(&self.evm_verifier, &p.clone().into())
                        .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;
                    Ok(())
                }
                ProofEnum::Stark(p) => Self::verify_stark_proof(p, &proof.vk),
            }
        }
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;

        let root_proof = chunk_proof.proof.as_stark_proof().unwrap();

        UniversalVerifier::verify_stark_proof(root_proof, &chunk_proof.vk)?;

        Ok(())
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;

        let stark_proof = batch_proof.proof.as_stark_proof().unwrap();

        UniversalVerifier::verify_stark_proof(stark_proof, &batch_proof.vk)?;

        Ok(())
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_bundle_proof() -> eyre::Result<()> {
        let evm_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        let verifier = UniversalVerifier::setup(Path::new(PATH_TESTDATA).join("verifier.bin"))?;

        verifier.verify_evm_proof(
            &evm_proof.proof.into_evm_proof().unwrap().into(),
            &evm_proof.vk,
        )?;

        Ok(())
    }
}
