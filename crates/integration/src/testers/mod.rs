pub mod batch;

pub mod bundle;

pub mod chunk;

/// Path to the testdata directory.
pub const PATH_TESTDATA: &str = "./testdata";

use super::testdata_fork_directory;
use scroll_zkvm_prover::utils::read_json_deep;
use scroll_zkvm_types::task::ProvingTask as UnivProvingTask;

/// Load universal task from file
pub fn load_local_task(task_name: &str) -> eyre::Result<UnivProvingTask> {
    Ok(read_json_deep(
        std::path::Path::new(PATH_TESTDATA)
            .join(testdata_fork_directory())
            .join("tasks")
            .join(task_name),
    )?)
}

use scroll_zkvm_prover::Prover;
struct UnsafeSendWrappedProver(Prover);

unsafe impl Send for UnsafeSendWrappedProver {}
