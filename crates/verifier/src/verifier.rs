use std::{marker::PhantomData, path::Path};
use once_cell::sync::Lazy;

use openvm_circuit::{system::program::trace::VmCommittedExe};
use scroll_zkvm_types::proof::OpenVmEvmProof;
use openvm_continuations::verifier::root::types::RootVmVerifierInput;
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{halo2::RawEvmProof, hints::Hintable};
use openvm_sdk::{commit::{AppExecutionCommit, CommitBytes}, config::AggStarkConfig, keygen::AggStarkProvingKey, types::EvmProof, RootSC, Sdk, F, SC};
use scroll_zkvm_types::{proof::RootProof, types_agg::{AggregationInput, ProgramCommitment}};
use snark_verifier_sdk::snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use tracing::{debug, instrument};

use crate::commitments::{
    batch::{EXE_COMMIT as BATCH_EXE_COMMIT, LEAF_COMMIT as BATCH_LEAF_COMMIT},
    bundle,
    chunk::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT},
};


/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()).unwrap());

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

pub struct Rv32ChunkVerifierType;
pub struct ChunkVerifierType;
pub struct BatchVerifierType;
pub struct BundleVerifierTypeEuclidV1;
pub struct BundleVerifierTypeEuclidV2;

impl VerifierType for ChunkVerifierType {
    const EXE_COMMIT: [u32; 8] = CHUNK_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = CHUNK_LEAF_COMMIT;
}

impl VerifierType for BatchVerifierType {
    const EXE_COMMIT: [u32; 8] = BATCH_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = BATCH_LEAF_COMMIT;
}
impl VerifierType for BundleVerifierTypeEuclidV2 {
    const EXE_COMMIT: [u32; 8] = bundle::EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = bundle::LEAF_COMMIT;
}

pub struct UniversalVerifier {
    //pub vm_executor: SingleSegmentVmExecutor<F, NativeConfig>,
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
            //SingleSegmentVmExecutor::new(vm_config)
        };

        let root_committed_exe = std::fs::read(path_root_committed_exe.as_ref())
            .map_err(|e| e.into())
            .and_then(|bytes| bincode_v1::deserialize(&bytes))?;

        let evm_verifier = std::fs::read(path_verifier_code.as_ref())?;

        Ok(Self {
            //vm_executor,
            root_committed_exe,
            evm_verifier,
        })
    }

    pub fn verify_proof(
        &self,
        root_proof: &RootProof,
        vk: &[u8],
    ) -> eyre::Result<bool> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        let ret = verify_proof_inner(root_proof, prog_commit.exe, prog_commit.leaf).is_ok();

        Ok(ret)
    }

    pub fn verify_proof_evm(&self, evm_proof: &OpenVmEvmProof, vk: &[u8]) -> eyre::Result<bool> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        if evm_proof.app_commit.app_exe_commit.to_u32_digest() != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.app_commit.app_vm_commit.to_u32_digest() != prog_commit.leaf {
            eyre::bail!("evm: mismatch LEAF commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof)
            .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

        Ok(true)
    }

    /* 
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
    */
}

pub struct Verifier<Type> {
    //pub vm_executor: SingleSegmentVmExecutor<F, NativeConfig>,
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: Vec<u8>,

    _type: PhantomData<Type>,
}

pub type AnyVerifier = Verifier<ChunkVerifierType>;
pub type ChunkVerifier = Verifier<ChunkVerifierType>;
pub type BatchVerifier = Verifier<BatchVerifierType>;
pub type BundleVerifierEuclidV1 = Verifier<BundleVerifierTypeEuclidV1>;
pub type BundleVerifierEuclidV2 = Verifier<BundleVerifierTypeEuclidV2>;

impl<Type> Verifier<Type> {
    pub fn setup<P: AsRef<Path>>(
        path_vm_config: P,
        path_root_committed_exe: P,
        path_verifier_code: P,
    ) -> eyre::Result<Self> {
        let vm_executor = {
            let bytes = std::fs::read(path_vm_config.as_ref())?;
            let vm_config: NativeConfig = bincode_v1::deserialize(&bytes)?;
            //SingleSegmentVmExecutor::new(vm_config)
        };

        let root_committed_exe = std::fs::read(path_root_committed_exe.as_ref())
            .map_err(|e| e.into())
            .and_then(|bytes| bincode_v1::deserialize(&bytes))?;

        let evm_verifier = std::fs::read(path_verifier_code.as_ref())?;

        Ok(Self {
            //vm_executor,
            root_committed_exe,
            evm_verifier,
            _type: PhantomData,
        })
    }

    pub fn switch_to<AnotherType>(self) -> Verifier<AnotherType> {
        Verifier::<AnotherType> {
            //vm_executor: self.vm_executor,
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
    pub fn to_bundle_verifier_v1(self) -> BundleVerifierEuclidV1 {
        self.switch_to()
    }
    pub fn to_bundle_verifier_v2(self) -> BundleVerifierEuclidV2 {
        self.switch_to()
    }
}

impl<Type: VerifierType> Verifier<Type> {
    pub fn get_app_vk(&self) -> Vec<u8> {
        Type::get_app_vk()
    }

    pub fn verify_proof(&self, root_proof: &RootProof) -> bool {
        verify_proof_inner(root_proof, Type::EXE_COMMIT, Type::LEAF_COMMIT).is_ok()
    }

    pub fn verify_proof_evm(&self, evm_proof: &OpenVmEvmProof) -> bool {
        assert_eq!(
            evm_proof.app_commit.app_exe_commit.to_u32_digest(),
            Type::EXE_COMMIT,
            "mismatch EXE commitment"
        );
        assert_eq!(
            evm_proof.app_commit.app_vm_commit.to_u32_digest(),
             Type::LEAF_COMMIT,
            "mismatch LEAF commitment"
        );
        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof).is_ok()
    }
}

    /// Verify a [root proof][root_proof].
    /// TODO: currently this method is only used in testing. Move it else
    /// [root_proof][RootProof]
    //#[instrument("Prover::verify_proof", skip_all, fields(?metadata = proof.metadata))]
    pub fn verify_proof_inner(root_proof: &RootProof, exe_commit: [u32; 8], vm_commit: [u32;8]) -> Result<(), String> {
        let agg_stark_pk = &AGG_STARK_PROVING_KEY;
        let sdk = Sdk::new();
        sdk.verify_e2e_stark_proof(agg_stark_pk,root_proof,
                &CommitBytes::from_u32_digest(&exe_commit).to_bn254(),
                &CommitBytes::from_u32_digest(&vm_commit).to_bn254(),
            ).unwrap();

                /* 
        let root_verifier_pk = &agg_stark_pk.root_verifier_pk;
        let vm_vk = root_verifier_pk.vm_pk.vm_pk.get_vk();

        let vm_executor = SingleSegmentVmExecutor::new(root_verifier_pk.vm_pk.vm_config.clone());
        let exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        println!("verify metric {:?} {:?} ", vm_vk.total_widths(), vm_vk.num_interactions());
        let max_trace_heights = vm_executor
            .execute_metered(
                exe.exe.clone(),
                root_proof.write(),
                &vm_vk.total_widths(),
                &vm_vk.num_interactions(),
            )
            .unwrap();
             println!("verify metric {:?} ", max_trace_heights);
            /* 
        let root_proof = proof.proof.as_root_proof().ok_or(
            "verify_proof expects RootProof".to_string(),
        )?;
        */
        let exec_res = vm_executor
            .execute_and_compute_heights(exe.exe.clone(), root_proof.write(), &max_trace_heights)
            .map_err(|e| e.to_string())?;
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        let pi = exec_res
                    .public_values
                    .iter()
                    .map(|op_f| op_f.map(|f| f.as_canonical_u32()))
                    .collect();

            /* 
        let aggregation_input = AggregationInput::from(proof);
        if aggregation_input.commitment.exe != Type::EXE_COMMIT {
            return Err(format!(
                "EXE_COMMIT mismatch: expected={:?}, got={:?}",
                Type::EXE_COMMIT,
                aggregation_input.commitment.exe,
            ));
        }
        if aggregation_input.commitment.leaf != Type::LEAF_COMMIT {
            return Err(format!(
                "LEAF_COMMIT mismatch: expected={:?}, got={:?}",
                Type::LEAF_COMMIT,
                aggregation_input.commitment.leaf,
            ));
        }
        */

        Ok(pi)
        */
        Ok(())
    }


    /* 
    pub(crate) fn verify_proof_inner_old(
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
    */


#[cfg(test)]
mod tests {
    use std::path::Path;

    use scroll_zkvm_prover::{
        AsRootProof, BatchProof, BundleProof, ChunkProof, IntoEvmProof, PersistableProof,
    };
    use scroll_zkvm_types::types_agg::ProgramCommitment;

    use super::*;

    const PATH_TESTDATA: &str = "./testdata";

    #[ignore = "need release assets"]
    #[test]
    fn verify_universal_proof() -> eyre::Result<()> {
        let chunk_proof = ChunkProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;
        let batch_proof = BatchProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;
        let evm_proof = BundleProof::from_json(
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
            chunk_proof.as_root_proof(),
            &ChunkVerifierType::get_app_vk(),
        )?;
        verifier.verify_proof(
            batch_proof.as_root_proof(),
            &BatchVerifierType::get_app_vk(),
        )?;
        verifier.verify_proof_evm(
            &evm_proof.into_evm_proof(),
            &BundleVerifierTypeEuclidV2::get_app_vk(),
        )?;

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = ChunkProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = ChunkVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&chunk_proof.vk);
        let root_proof = chunk_proof.as_root_proof();
        let pi = verify_proof_inner(root_proof, commitment.exe, commitment.leaf).unwrap();
        assert!(
            verifier.verify_proof(root_proof),
            "proof verification failed",
        );

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = BatchProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;

        let verifier = BatchVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&batch_proof.vk);
        let root_proof = batch_proof.as_root_proof();
        verify_proof_inner(root_proof, commitment.exe, commitment.leaf).unwrap();

        Ok(())
    }

    #[ignore = "need released assets"]
    #[test]
    fn verify_bundle_proof() -> eyre::Result<()> {
        let evm_proof = BundleProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        let verifier = BundleVerifierEuclidV2::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-vm-config"),
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        assert!(verifier.verify_proof_evm(&evm_proof.into_evm_proof()));

        Ok(())
    }
}
