use std::path::Path;

use scroll_zkvm_prover::{
    Prover, task::ProvingTask, utils::read_json_deep,
};
use scroll_zkvm_types::{
    proof::ProofEnum,
    public_inputs::ForkName,
    chunk::{ChunkInfo, ChunkWitness},
    batch::{BatchInfo, BatchWitness, BatchHeader, ReferenceHeader},
};

use crate::{
    ProverTester, PartialProvingTask, TestTaskBuilder,
    testdata_fork_directory,
    testers::{PATH_TESTDATA, chunk::ChunkProverTester},
    utils::build_batch_task,
    testers::chunk::ChunkTaskGenerator,
};


impl PartialProvingTask for BatchWitness {
    fn identifier(&self) -> String {
        let header_hash = match &self.reference_header {
            ReferenceHeader::V6(h) => h.batch_hash(),
            ReferenceHeader::V7(h) => h.batch_hash(),
            ReferenceHeader::V8(h) => h.batch_hash(),
        };
        header_hash.to_string()
    }

    fn write_guest_input(&self, stdin: &mut openvm_sdk::StdIn) -> Result<(), rkyv::rancor::Error> {
        let b = rkyv::to_bytes::<rkyv::rancor::Error>(self)?;
        stdin.write_bytes(b.as_slice());
        Ok(())
    }

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }    
}


pub struct BatchProverTester;

impl ProverTester for BatchProverTester {

    type Metadata = BatchInfo;

    type Witness = BatchWitness;

    const NAME: &str = "batch";

    const PATH_PROJECT_ROOT: &str = "crates/circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";
}

pub struct BatchTaskGenerator (pub Vec<ChunkTaskGenerator>);

impl TestTaskBuilder<BatchProverTester> for BatchTaskGenerator {

    fn gen_proving_witnesses(&self) -> eyre::Result<BatchWitness>{
        unimplemented!();
    }

    fn gen_witnesses_proof(&self, prover: &Prover) -> eyre::Result<ProofEnum>{
        unimplemented!();
    }
}

//     fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
//         Ok(read_json_deep(
//             Path::new(PATH_TESTDATA)
//                 .join(testdata_fork_directory())
//                 .join("tasks")
//                 .join("batch-task.json"),
//         )?)
//     }

pub struct BatchTaskBuildingTester;

impl ProverTester for BatchTaskBuildingTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "crates/circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        let chunk_task = ChunkProverTester::gen_proving_task()?;

        let proof_path = Path::new(PATH_TESTDATA)
            .join(testdata_fork_directory())
            .join("proofs")
            .join(format!("chunk-{}.json", chunk_task.identifier()));
        println!("proof_path: {:?}", proof_path);

        let chunk_proof = read_json_deep::<_, ChunkProof>(&proof_path)?;

        let task = build_batch_task(&[chunk_task], &[chunk_proof], Default::default());
        Ok(task)
    }
}

#[test]
fn batch_task_parsing() {
    use scroll_zkvm_prover::task::ProvingTask;

    let task = BatchProverTester::gen_proving_task().unwrap();

    let _ = task.build_guest_input().unwrap();
}
