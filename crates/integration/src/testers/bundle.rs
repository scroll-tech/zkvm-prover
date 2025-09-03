use scroll_zkvm_types::{
    batch::BatchInfo,
    bundle::{BundleInfo, BundleWitness},
    proof::ProofEnum,
    public_inputs::ForkName,
};

// Only related to hardcoded commitments. Can be refactored later.
use scroll_zkvm_prover::Prover;

use crate::{
    PartialProvingTask, ProverTester, load_program_commitments, prove_verify_single_evm,
    testers::batch::BatchTaskGenerator, utils::metadata_from_batch_witnesses,
};

impl PartialProvingTask for BundleWitness {
    fn identifier(&self) -> String {
        let (first, last) = (
            self.batch_infos.first().expect("MUST NOT EMPTY").batch_hash,
            self.batch_infos.last().expect("MUST NOT EMPTY").batch_hash,
        );

        format!("{first}-{last}")
    }

    fn legacy_rkyv_archive(&self) -> eyre::Result<Vec<u8>> {
        Ok(rkyv::to_bytes::<rkyv::rancor::Error>(self)?.to_vec())
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

pub struct BundleTaskGenerator {
    witness: Option<BundleWitness>,
    batch_generators: Vec<BatchTaskGenerator>,
    proof: Option<ProofEnum>,
}

impl BundleTaskGenerator {
    pub fn get_or_build_witness(&mut self) -> eyre::Result<BundleWitness> {
        if self.witness.is_some() {
            return Ok(self.witness.clone().unwrap());
        }
        let witness = self.calculate_witness()?;
        self.witness.replace(witness.clone());
        Ok(witness)
    }

    pub fn get_or_build_proof(
        &mut self,
        prover: &mut Prover,
        batch_prover: &mut Prover,
        chunk_prover: &mut Prover,
    ) -> eyre::Result<ProofEnum> {
        if let Some(proof) = &self.proof {
            return Ok(proof.clone());
        }
        let wit = self.get_or_build_witness()?;
        let agg_proofs = self.get_or_build_child_proofs(batch_prover, chunk_prover)?;
        let proof = prove_verify_single_evm::<BundleProverTester>(prover, &wit, &agg_proofs)?;
        self.proof.replace(proof.clone());
        Ok(proof)
    }

    fn get_or_build_child_proofs(
        &mut self,
        batch_prover: &mut Prover,
        chunk_prover: &mut Prover,
    ) -> eyre::Result<Vec<ProofEnum>> {
        let mut proofs = Vec::new();
        for chunk_gen in &mut self.batch_generators {
            let proof = chunk_gen.get_or_build_proof(batch_prover, chunk_prover)?;
            proofs.push(proof);
        }
        Ok(proofs)
    }

    /// accept a series of BatchTaskGenerator, must be validated in advanced (continuous)
    pub fn from_batch_tasks(batches: &[BatchTaskGenerator]) -> Self {
        Self {
            witness: None,
            batch_generators: batches.to_vec(),
            proof: None,
        }
    }

    fn calculate_witness(&mut self) -> eyre::Result<BundleWitness> {
        use scroll_zkvm_types::{
            public_inputs::MultiVersionPublicInputs, types_agg::AggregationInput,
        };

        let version = self
            .batch_generators
            .first()
            .expect("at least 1 batch in a bundle")
            .version();
        let fork_name = version.fork;

        let commitment = load_program_commitments("batch")?;
        let mut batch_proofs = Vec::new();
        let mut batch_infos: Vec<BatchInfo> = Vec::new();

        for generator in &mut self.batch_generators {
            let wit = generator.get_or_build_witness()?;
            let info = metadata_from_batch_witnesses(&wit)?;
            if let Some(last_info) = batch_infos.last() {
                // validate some data
                assert_eq!(info.parent_state_root, last_info.state_root, "state root");
                assert_eq!(info.chain_id, last_info.chain_id, "chain id");
                assert_eq!(info.parent_batch_hash, last_info.batch_hash, "batch hash",);
            }

            let pi_hash = info.pi_hash_by_version(version);
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
            version: version.as_version_byte(),
            batch_infos,
            batch_proofs,
            fork_name,
        })
    }
}
