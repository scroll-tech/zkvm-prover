use scroll_zkvm_types::{
    batch::BatchInfo,
    bundle::{BundleInfo, BundleWitness},
    proof::ProofEnum,
    public_inputs::ForkName,
};

// Only related to hardcoded commitments. Can be refactored later.
use scroll_zkvm_prover::Prover;

use crate::{
    PartialProvingTask, ProverTester, TestTaskBuilder, prove_verify_single_evm,
    testers::batch::{BatchProverTester, BatchTaskGenerator},
    testing_hardfork,
    utils::metadata_from_batch_witnesses,
};

use std::sync::OnceLock;

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
}

#[derive(Debug)]
pub struct BundleTaskGenerator {
    result: OnceLock<eyre::Result<BundleWitness>>,
    batch_generators: Vec<BatchTaskGenerator>,
}

impl TestTaskBuilder<BundleProverTester> for BundleTaskGenerator {
    fn gen_proving_witnesses(&self) -> eyre::Result<BundleWitness> {
        self.result
            .get_or_init(|| self.calculate_bundle_witness())
            .as_ref()
            .map_err(|e| eyre::eyre!("{e}"))
            .cloned()
    }

    fn gen_agg_proofs(&self, prover: &mut Prover) -> eyre::Result<Vec<ProofEnum>> {
        let mut batch_prover = BatchProverTester::load_prover(false)?;
        let batch_proofs = self
            .batch_generators
            .iter()
            .map(|generator| generator.gen_witnesses_proof(&mut batch_prover))
            .collect::<Result<Vec<ProofEnum>, _>>()?;

        Ok(batch_proofs)
    }

    fn gen_witnesses_proof(&self, prover: &mut Prover) -> eyre::Result<ProofEnum> {
        let wit = self.gen_proving_witnesses()?;
        let agg_proofs = self.gen_agg_proofs(prover)?;
        let (proof, _, _) =
            prove_verify_single_evm::<BundleProverTester>(prover, &wit, &agg_proofs)?;
        Ok(proof)
    }
}

impl BundleTaskGenerator {
    /// accept a series of BatchTaskGenerator, must be validated in advanced (continuous)
    pub fn from_batch_tasks(batches: &[BatchTaskGenerator]) -> Self {
        Self {
            result: OnceLock::new(),
            batch_generators: batches.to_vec(),
        }
    }

    fn calculate_bundle_witness(&self) -> eyre::Result<BundleWitness> {
        use scroll_zkvm_types::{
            public_inputs::MultiVersionPublicInputs,
            types_agg::{AggregationInput, ProgramCommitment},
        };

        let fork_name = testing_hardfork();
        let mut batch_prover = BatchProverTester::load_prover(false)?;
        let vk = batch_prover.get_app_vk();
        let commitment = ProgramCommitment::deserialize(&vk);
        let mut batch_proofs = Vec::new();
        let mut batch_infos: Vec<BatchInfo> = Vec::new();

        for generator in &self.batch_generators {
            let wit = generator.gen_proving_witnesses()?;
            let info = metadata_from_batch_witnesses(&wit)?;
            if let Some(last_info) = batch_infos.last() {
                // validate some data
                assert_eq!(info.parent_state_root, last_info.state_root, "state root");
                assert_eq!(info.chain_id, last_info.chain_id, "chain id");
                assert_eq!(info.parent_batch_hash, last_info.batch_hash, "batch hash",);
            }

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
