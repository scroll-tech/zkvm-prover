mod chunk_exe_commit;
mod chunk_leaf_commit;

pub const EXE_COMMIT: [u32; 8] = chunk_exe_commit::COMMIT;
pub const LEAF_COMMIT: [u32; 8] = chunk_leaf_commit::COMMIT;
