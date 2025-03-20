use std::{marker::PhantomData, path::Path};

use itertools::Itertools;
use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_continuations::verifier::root::types::RootVmVerifierInput;
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{
    halo2::{EvmProof, wrapper::EvmVerifier},
    hints::Hintable,
};
use openvm_sdk::{F, RootSC, SC};
use scroll_zkvm_circuit_input_types::proof::ProgramCommitment;

use crate::commitments::bundle::{
    EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT,
};

use crate::commitments::{
    batch::{EXE_COMMIT as BATCH_EXE_COMMIT, LEAF_COMMIT as BATCH_LEAF_COMMIT},
    chunk::{EXE_COMMIT as BUNDLE_EXE_COMMIT, LEAF_COMMIT as BUNDLE_LEAF_COMMIT},
};

pub trait VerifierType {
    const EXE_COMMIT: [u32; 8];
    const LEAF_COMMIT: [u32; 8];
    fn get_app_vk() -> Vec<u8> {
        ProgramCommitment {
            exe: Self::EXE_COMMIT,
            leaf: Self::LEAF_COMMIT,
        }
        .serialize()
    }
}

pub struct ChunkVerifierType;
pub struct BatchVerifierType;
pub struct BundleVerifierType;

impl VerifierType for ChunkVerifierType {
    const EXE_COMMIT: [u32; 8] = CHUNK_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = CHUNK_LEAF_COMMIT;
}
impl VerifierType for BatchVerifierType {
    const EXE_COMMIT: [u32; 8] = BATCH_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = BATCH_LEAF_COMMIT;
}
impl VerifierType for BundleVerifierType {
    const EXE_COMMIT: [u32; 8] = BUNDLE_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = BUNDLE_LEAF_COMMIT;
}

pub struct Verifier<Type> {
    pub vm_executor: SingleSegmentVmExecutor<F, NativeConfig>,
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: EvmVerifier,

    _type: PhantomData<Type>,
}

pub type ChunkVerifier = Verifier<ChunkVerifierType>;
pub type BatchVerifier = Verifier<BatchVerifierType>;
pub type BundleVerifier = Verifier<BundleVerifierType>;

impl<Type> Verifier<Type> {
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

        let evm_verifier = std::fs::read(path_verifier_code.as_ref()).map(EvmVerifier)?;

        Ok(Self {
            vm_executor,
            root_committed_exe,
            evm_verifier,
            _type: PhantomData,
        })
    }

    pub fn switch_to<AnotherType>(self) -> Verifier<AnotherType> {
        Verifier::<AnotherType> {
            vm_executor: self.vm_executor,
            root_committed_exe: self.root_committed_exe,
            evm_verifier: self.evm_verifier,
            _type: PhantomData,
        }
    }

    pub fn to_chunk_verifier(self) -> ChunkVerifier {
        self.switch_to()
    }
    pub fn to_batch_verifier(self) -> BatchVerifier {
        self.switch_to()
    }
    pub fn to_bundle_verifier(self) -> BundleVerifier {
        self.switch_to()
    }
}

impl<Type: VerifierType> Verifier<Type> {
    pub fn get_app_vk(&self) -> Vec<u8> {
        Type::get_app_vk()
    }

    pub fn verify_proof(&self, root_proof: &RootVmVerifierInput<SC>) -> bool {
        match self.verify_proof_inner(root_proof) {
            Ok(pi) => {
                assert!(pi.len() >= 16, "unexpected len(pi)<16");
                assert!(
                    pi.iter().take(8).zip_eq(Type::EXE_COMMIT.iter()).all(
                        |(op_found, &expected)| op_found.is_some_and(|found| found == expected)
                    ),
                    "mismatch EXE commitment"
                );
                assert!(
                    pi.iter()
                        .skip(8)
                        .take(8)
                        .zip_eq(Type::LEAF_COMMIT.iter())
                        .all(
                            |(op_found, &expected)| op_found.is_some_and(|found| found == expected)
                        ),
                    "mismatch LEAF commitment"
                );
                true
            }
            Err(_) => false,
        }
    }

    pub fn verify_proof_evm(&self, evm_proof: &EvmProof) -> bool {
        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof).is_ok()
    }

    pub(crate) fn verify_proof_inner(
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

    use scroll_zkvm_circuit_input_types::proof::ProgramCommitment;
    use scroll_zkvm_prover::{BatchProof, BundleProof, ChunkProof, utils::read_json_deep};

    use super::{BatchVerifier, ChunkVerifier};

    const PATH_TESTDATA: &str = "./testdata";

    #[ignore = "need release assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof =
            read_json_deep::<_, ChunkProof>(Path::new(PATH_TESTDATA).join("proofs").join(
                if cfg!(feature = "euclidv2") {
                    "chunk-proof-phase2.json"
                } else {
                    "chunk-proof-phase1.json"
                },
            ))?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = ChunkVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&chunk_proof.vk);
        let root_proof = chunk_proof.as_proof();
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
            verifier.verify_proof(root_proof),
            "proof verification failed",
        );

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = read_json_deep::<_, BatchProof>(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof.json"),
        )?;

        let verifier = BatchVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&batch_proof.vk);
        let root_proof = batch_proof.as_proof();
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
            verifier.verify_proof(root_proof),
            "proof verification failed",
        );

        Ok(())
    }

    #[ignore = "need released assets"]
    #[test]
    fn verify_bundle_proof() -> eyre::Result<()> {
        use openvm_stark_sdk::{
            openvm_stark_backend::p3_field::PrimeField32, p3_baby_bear::BabyBear,
        };
        use snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::Fr;

        let compress_commitment = |commitment: &[u32; 8]| -> Fr {
            let order = Fr::from(BabyBear::ORDER_U32 as u64);
            let mut base = Fr::one();
            let mut ret = Fr::zero();

            for v in commitment {
                ret += Fr::from(*v as u64) * base;
                base *= order;
            }

            ret
        };

        let evm_proof = read_json_deep::<_, BundleProof>(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("evm-proof.json"),
        )?;

        let verifier = BatchVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        assert_eq!(
            evm_proof.as_proof().instances[0][12],
            compress_commitment(&super::BUNDLE_EXE_COMMIT),
            "the output is not match with exe commitment in evm proof!"
        );
        assert_eq!(
            evm_proof.as_proof().instances[0][13],
            compress_commitment(&super::BUNDLE_LEAF_COMMIT),
            "the output is not match with leaf commitment in evm proof!"
        );

        assert!(verifier.verify_proof_evm(&evm_proof.as_proof()));

        Ok(())
    }
}
