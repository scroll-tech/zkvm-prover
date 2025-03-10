use std::{marker::PhantomData, path::Path};

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{
    halo2::{EvmProof, wrapper::EvmVerifier},
    hints::Hintable,
};
use openvm_sdk::{F, RootSC, SC, verifier::root::types::RootVmVerifierInput};
use scroll_zkvm_circuit_input_types::proof::ProgramCommitment;

use crate::commitments::{
    batch::{EXE_COMMIT as BATCH_EXE_COMMIT, LEAF_COMMIT as BATCH_LEAF_COMMIT},
    bundle::{EXE_COMMIT as BUNDLE_EXE_COMMIT, LEAF_COMMIT as BUNDLE_LEAF_COMMIT},
    chunk::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT},
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
    pub evm_verifier: Option<EvmVerifier>,

    _type: PhantomData<Type>,
}

pub type ChunkVerifier = Verifier<ChunkVerifierType>;
pub type BatchVerifier = Verifier<BatchVerifierType>;
pub type BundleVerifier = Verifier<BundleVerifierType>;

impl<Type> Verifier<Type> {
    pub fn setup<P: AsRef<Path>>(
        path_vm_config: P,
        path_root_committed_exe: P,
        path_verifier_code: Option<P>,
    ) -> eyre::Result<Self> {
        let vm_executor = {
            let bytes = std::fs::read(path_vm_config.as_ref())?;
            let vm_config: NativeConfig = bincode::deserialize(&bytes)?;
            SingleSegmentVmExecutor::new(vm_config)
        };

        let root_committed_exe = {
            std::fs::read(path_root_committed_exe.as_ref())
            .map_err(|e|e.into())
            .and_then(|bytes|bincode_v1::deserialize(&bytes))
            .unwrap_or_else(|e|{
                use openvm_sdk::{config::AggStarkConfig, keygen::AggStarkProvingKey};
                println!("can not load committed exe, try to create it (may take quite a long time) {e}");
                let (agg_stark_pk, _) = AggStarkProvingKey::dummy_proof_and_keygen(AggStarkConfig::default());
                agg_stark_pk.root_verifier_pk.root_committed_exe.as_ref().clone()
            })
        };

        let evm_verifier = path_verifier_code
            .and_then(|p| std::fs::read(p.as_ref()).ok())
            .map(EvmVerifier);

        Ok(Self {
            vm_executor,
            root_committed_exe,
            evm_verifier,
            _type: PhantomData,
        })
    }
}

impl<Type: VerifierType> Verifier<Type> {
    pub fn get_app_vk(&self) -> Vec<u8> {
        Type::get_app_vk()
    }

    pub fn verify_proof(&self, root_proof: &RootVmVerifierInput<SC>) -> bool {
        let ret = self.verify_proof_with_pi(root_proof);
        if let Ok(ret) = ret {
            // if fail here we need to consider what happen for root committed exe (wrong code or openvm has a breaking change?)
            assert!(ret.len() >= 16, "unexpected reveal pi from committed exe");
            ret.iter()
                .zip(&Type::EXE_COMMIT)
                .all(|(r_pi, exe_cmt)| r_pi.as_ref() == Some(exe_cmt))
                && ret[8..]
                    .iter()
                    .zip(&Type::LEAF_COMMIT)
                    .all(|(r_pi, exe_cmt)| r_pi.as_ref() == Some(exe_cmt))
        } else {
            false
        }
    }

    pub fn verify_proof_with_pi(
        &self,
        root_proof: &RootVmVerifierInput<SC>,
    ) -> eyre::Result<Vec<Option<u32>>> {
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        let ret = self
            .vm_executor
            .execute_and_compute_heights(self.root_committed_exe.exe.clone(), root_proof.write())
            .map(|r| {
                r.public_values
                    .iter()
                    .map(|op_f| op_f.map(|f| f.as_canonical_u32()))
                    .collect::<Vec<_>>()
            })?;
        Ok(ret)
    }

    pub fn verify_proof_evm(&self, evm_proof: &EvmProof) -> bool {
        crate::evm::verify_evm_proof(self.evm_verifier.as_ref().unwrap(), evm_proof).is_ok()
    }
}

#[test]
fn verify_chunk_proof() {
    use scroll_zkvm_prover::{ChunkProof, utils::read_json_deep};
    let chunk_proof = read_json_deep::<_, ChunkProof>(
        "../integration/testdata/proofs/chunk-12508460-12508463.json",
    )
    .unwrap();

    let commitment = ProgramCommitment::deserialize(&chunk_proof.vk);

    let test_path = "../../releases/0.1.0-rc.6/verifier";
    let verifier = ChunkVerifier::setup(
        Path::new(test_path).join("root-verifier-vm-config"),
        Path::new(test_path).join("root-verifier-committed-exe"),
        None,
    )
    .unwrap();

    let root_proof = chunk_proof.as_proof();
    let ret = verifier.verify_proof_with_pi(root_proof).unwrap();
    assert_eq!(
        &ret[..8],
        commitment.exe.map(Some).as_slice(),
        "the output is not match with exe commitment in root proof!"
    );
    assert_eq!(
        &ret[8..16],
        commitment.leaf.map(Some).as_slice(),
        "the output is not match with leaf commitment in root proof!"
    );

    assert!(
        verifier.verify_proof(root_proof),
        "vk in root proof is not match with hard encoded commitment"
    );
}
