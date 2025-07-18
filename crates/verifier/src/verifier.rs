use std::path::Path;

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_continuations::verifier::root::types::RootVmVerifierInput;
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{halo2::RawEvmProof, hints::Hintable};
use openvm_sdk::{F, RootSC, SC};
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

pub struct UniversalVerifier {
    pub vm_executor: SingleSegmentVmExecutor<F, NativeConfig>,
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: Vec<u8>,
}

impl UniversalVerifier {
    pub fn setup<P: AsRef<Path>>(
        path_vm_config: P,
        path_root_committed_exe: P,
        path_verifier_code: P,
    ) -> eyre::Result<Self> {
        let vm_executor = {
            let bytes = std::fs::read(path_vm_config.as_ref())?;
            let vm_config: NativeConfig = bincode_v1::deserialize(&bytes)?;
            SingleSegmentVmExecutor::new(vm_config)
        };

        let root_committed_exe = std::fs::read(path_root_committed_exe.as_ref())
            .map_err(|e| e.into())
            .and_then(|bytes| bincode_v1::deserialize(&bytes))?;

        let evm_verifier = std::fs::read(path_verifier_code.as_ref())?;

        Ok(Self {
            vm_executor,
            root_committed_exe,
            evm_verifier,
        })
    }

    pub fn verify_proof(
        &self,
        root_proof: &RootVmVerifierInput<SC>,
        vk: &[u8],
    ) -> eyre::Result<bool> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        let ret = match self.verify_proof_inner(root_proof) {
            Ok(pi) => {
                assert!(pi.len() >= 16, "unexpected len(pi)<16");
                if &pi[..8] != prog_commit.exe.map(Some).as_slice() {
                    eyre::bail!("mismatch EXE commitment");
                }
                if &pi[8..16] != prog_commit.leaf.map(Some).as_slice() {
                    eyre::bail!("mismatch LEAF commitment");
                }
                true
            }
            Err(e) => eyre::bail!("unknown issue: {e}"),
        };

        Ok(ret)
    }

    pub fn verify_proof_evm(&self, evm_proof: &RawEvmProof, vk: &[u8]) -> eyre::Result<bool> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        if evm_proof.instances[12] != compress_commitment(&prog_commit.exe) {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.instances[13] != compress_commitment(&prog_commit.leaf) {
            eyre::bail!("evm: mismatch EXE commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof)
            .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

        Ok(true)
    }

    fn verify_proof_inner(
        &self,
        root_proof: &RootVmVerifierInput<SC>,
    ) -> eyre::Result<Vec<Option<u32>>> {
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        Ok(self
            .vm_executor
            .execute_and_compute_heights(self.root_committed_exe.exe.clone(), root_proof.write())
            .map(|exec_res| {
                exec_res
                    .public_values
                    .iter()
                    .map(|op_f| op_f.map(|f| f.as_canonical_u32()))
                    .collect()
            })?)
    }
}


#[cfg(test)]
mod tests {
    use std::path::Path;
    use crate::test::WrappedProof;
    use scroll_zkvm_types::types_agg::ProgramCommitment;

    use super::*;

    const PATH_TESTDATA: &str = "./testdata";

    #[ignore = "need release assets"]
    #[test]
    fn verify_universal_proof() -> eyre::Result<()> {
        let chunk_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;
        let batch_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;
        let evm_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        verifier.verify_proof(
            chunk_proof.proof.as_root_proof().unwrap(),
            &chunk_proof.vk,
        )?;
        verifier.verify_proof(
            batch_proof.proof.as_root_proof().unwrap(),
            &batch_proof.vk,
        )?;
        verifier.verify_proof_evm(
            &evm_proof.proof.into_evm_proof().unwrap().into(),
            &evm_proof.vk,
        )?;

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&chunk_proof.vk);
        let root_proof = chunk_proof.proof.as_root_proof().unwrap();
        let pi = verifier.verify_proof_inner(root_proof).unwrap();
        assert_eq!(
            &pi[..8],
            commitment.exe.map(Some).as_slice(),
            "the output is not match with exe commitment in root proof!",
        );
        assert_eq!(
            &pi[8..16],
            commitment.leaf.map(Some).as_slice(),
            "the output is not match with leaf commitment in root proof!",
        );
        assert!(
            verifier.verify_proof(root_proof, &chunk_proof.vk)?,
            "proof verification failed",
        );

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;

        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&batch_proof.vk);
        let root_proof = batch_proof.proof.as_root_proof().unwrap();
        let pi = verifier.verify_proof_inner(root_proof).unwrap();
        assert_eq!(
            &pi[..8],
            commitment.exe.map(Some).as_slice(),
            "the output is not match with exe commitment in root proof!",
        );
        assert_eq!(
            &pi[8..16],
            commitment.leaf.map(Some).as_slice(),
            "the output is not match with leaf commitment in root proof!",
        );
        assert!(
            verifier.verify_proof(root_proof, &batch_proof.vk)?,
            "proof verification failed",
        );

        Ok(())
    }

    #[ignore = "need released assets"]
    #[test]
    fn verify_bundle_proof() -> eyre::Result<()> {
        let evm_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        assert!(verifier.verify_proof_evm(&evm_proof.proof.into_evm_proof().unwrap().into(), &evm_proof.vk)?);

        Ok(())
    }
}
