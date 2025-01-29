use std::str::FromStr;

use scroll_zkvm_prover::{
    BatchProverType, ChunkProof, ProverType, task::chunk::ChunkProvingTask, utils::read_json,
};

use crate::{ProverTester, utils::build_batch_task};

// const PATH_BATCH_WITNESS: &str = "./testdata/batch-task.json";
const PATH_CHUNK_PROOFS: &str = "./testdata/proofs";
const BLK_PATHS: [&str; 4] = [
    "./testdata/12508460.json",
    "./testdata/12508461.json",
    "./testdata/12508462.json",
    "./testdata/12508463.json",
];

fn blk_witness(path: &str) -> eyre::Result<sbv::primitives::types::BlockWitness> {
    let w = read_json(path)?;
    Ok(w)
}

pub struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        let chk_task = [ChunkProvingTask {
            block_witnesses: Vec::from(BLK_PATHS.map(blk_witness).map(Result::unwrap)),
        }];
        let proof_names = ["chunk-12508460-12508463.json"];
        let chunk_proofs = proof_names.map(|n| {
            let p = format!("{PATH_CHUNK_PROOFS}/{n}");
            let mut proof = ChunkProof::from_json(p).unwrap();
            proof.metadata.chunk_info.withdraw_root = sbv::primitives::B256::from_str(
                "0x7ed4c7d56e2ed40f65d25eecbb0110f3b3f4db68e87700287c7e0cedcb68272c",
            )
            .unwrap();
            proof
        });
        Ok(build_batch_task(
            &chk_task,
            &chunk_proofs,
            scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
            Default::default(),
        ))
    }
}

pub struct MultiBatchProverTester;

impl ProverTester for MultiBatchProverTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        let chk_task = [
            ChunkProvingTask {
                block_witnesses: vec![blk_witness(BLK_PATHS[0])?],
            },
            ChunkProvingTask {
                block_witnesses: vec![blk_witness(BLK_PATHS[1])?],
            },
            ChunkProvingTask {
                block_witnesses: vec![blk_witness(BLK_PATHS[2])?, blk_witness(BLK_PATHS[3])?],
            },
        ];
        let proof_names = [
            "chunk-12508460-12508460.json",
            "chunk-12508461-12508461.json",
            "chunk-12508462-12508463.json",
        ];
        let chunk_proofs = proof_names.map(|n| {
            let p = format!("{PATH_CHUNK_PROOFS}/{n}");
            let mut proof = ChunkProof::from_json(p).unwrap();
            proof.metadata.chunk_info.withdraw_root = sbv::primitives::B256::from_str(
                "0x7ed4c7d56e2ed40f65d25eecbb0110f3b3f4db68e87700287c7e0cedcb68272c",
            )
            .unwrap();
            proof
        });
        Ok(build_batch_task(
            &chk_task,
            &chunk_proofs,
            scroll_zkvm_circuit_input_types::batch::MAX_AGG_CHUNKS,
            Default::default(),
        ))
    }

    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        todo!("BatchProverTester: gen_multi_proving_tasks not implemented")
    }
}
