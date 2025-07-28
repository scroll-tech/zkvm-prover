use scroll_zkvm_types::{
    batch::{BatchInfo, BatchWitness},
    bundle::{BundleInfo, BundleWitness},
    proof::ProofEnum,
    public_inputs::ForkName,
};

// Only related to hardcoded commitments. Can be refactored later.
use scroll_zkvm_prover::Prover;

use crate::{
    PartialProvingTask, ProverTester, TestTaskBuilder, prove_verify_single_evm,
    testers::{
        UnsafeSendWrappedProver,
        batch::{BatchProverTester, BatchTaskGenerator},
    },
    testing_hardfork,
};

use std::sync::{Mutex, OnceLock};

impl PartialProvingTask for BundleWitness {
    fn identifier(&self) -> String {
        let (first, last) = (
            self.batch_infos.first().expect("MUST NOT EMPTY").batch_hash,
            self.batch_infos.last().expect("MUST NOT EMPTY").batch_hash,
        );

        format!("{first}-{last}")
    }

    fn write_guest_input(&self, stdin: &mut openvm_sdk::StdIn) -> Result<(), rkyv::rancor::Error> {
        let b = self.rkyv_serialize(None)?;
        stdin.write_bytes(b.as_slice());
        Ok(())
    }

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }
}

pub struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Metadata = BundleInfo;

    type Witness = BundleWitness;

    const NAME: &str = "bundle";

    const PATH_PROJECT_ROOT: &str = "crates/circuits/bundle-circuit";

    const DIR_ASSETS: &str = "bundle";

    // fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
    //     Ok(BundleProvingTask {
    //         batch_proofs: vec![
    //             read_json_deep(Path::new(PATH_TESTDATA).join("proofs").join(
    //                 "batch-0x6a2d14504ccc86a2d1a3fb00f95e50cf2de80230fc51306d16b5f4ccc17b8e73.json",
    //             ))?,
    //             read_json_deep(Path::new(PATH_TESTDATA).join("proofs").join(
    //                 "batch-0x5f769da6d14efecf756c2a82c164416f31b3986d6c701479107acb1bcd421b21.json",
    //             ))?,
    //         ],
    //         bundle_info: None,
    //         fork_name: testing_hardfork().to_string(),
    //     })
    // }
}

impl BundleProverTester {
    fn instrinsic_batch_prover() -> eyre::Result<&'static Mutex<UnsafeSendWrappedProver>> {
        static BATCH_PROVER: OnceLock<eyre::Result<Mutex<UnsafeSendWrappedProver>>> =
            OnceLock::new();
        BATCH_PROVER
            .get_or_init(|| {
                BatchProverTester::load_prover(false)
                    .map(UnsafeSendWrappedProver)
                    .map(Mutex::new)
            })
            .as_ref()
            .map_err(|e| eyre::eyre!("{e}"))
    }
}

#[derive(Debug, Clone)]
pub struct BundleTaskGenerator {
    batch_generators: Vec<BatchTaskGenerator>,
}

fn metadata_from_batch_witnesses(witness: &BatchWitness) -> eyre::Result<BatchInfo> {
    use scroll_zkvm_types::batch::ArchivedBatchWitness;
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(witness)?;
    let archieved_wit = rkyv::access::<ArchivedBatchWitness, rkyv::rancor::BoxedError>(&bytes)?;
    Ok(archieved_wit.into())
}

impl TestTaskBuilder<BundleProverTester> for BundleTaskGenerator {
    fn gen_proving_witnesses(&self) -> eyre::Result<BundleWitness> {
        self.calculate_bundle_witness()
    }

    fn gen_agg_proofs(&self) -> eyre::Result<Vec<ProofEnum>> {
        let batch_prover = &BundleProverTester::instrinsic_batch_prover()?
            .lock()
            .unwrap()
            .0;
        let batch_proofs = self
            .batch_generators
            .iter()
            .map(|generator| generator.gen_witnesses_proof(batch_prover))
            .collect::<Result<Vec<ProofEnum>, _>>()?;

        Ok(batch_proofs)
    }

    fn gen_witnesses_proof(&self, prover: &Prover) -> eyre::Result<ProofEnum> {
        let wit = self.gen_proving_witnesses()?;
        let agg_proofs = self.gen_agg_proofs()?;
        let (proof, _, _) = prove_verify_single_evm::<BundleProverTester>(prover, &wit, &agg_proofs)?;
        Ok(proof)
    }    
}

impl BundleTaskGenerator {

    /// accept a series of BatchTaskGenerator, must be validated in advanced (continuous)
    pub fn from_batch_tasks(
        batches: &[BatchTaskGenerator],
    ) -> Self {
        Self {
            batch_generators: batches.to_vec(),
        }
    }

    fn calculate_bundle_witness(&self) -> eyre::Result<BundleWitness> {
        use scroll_zkvm_types::{
            public_inputs::MultiVersionPublicInputs,
            types_agg::{AggregationInput, ProgramCommitment},
        };

        let fork_name = testing_hardfork();
        let vk = BundleProverTester::instrinsic_batch_prover()?
            .lock()
            .unwrap()
            .0
            .get_app_vk();
        let commitment = ProgramCommitment::deserialize(&vk);
        let mut batch_proofs = Vec::new();
        let mut batch_infos = Vec::new();

        for generator in &self.batch_generators {
            let wit = generator.gen_proving_witnesses()?;
            let info = metadata_from_batch_witnesses(&wit)?;

            let pi_hash = info.pi_hash_by_fork(fork_name);
            let proof = AggregationInput {
                public_values: pi_hash
                    .as_slice()
                    .iter()
                    .map(|&b| b as u32)
                    .collect::<Vec<_>>(),
                commitment: commitment.clone(),
            };
            batch_proofs.push(proof);
            batch_infos.push(info);
        }

        Ok(BundleWitness {
            batch_infos,
            batch_proofs,
            fork_name,
        })
    }
}
