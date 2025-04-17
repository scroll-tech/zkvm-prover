mod chunk_exe_commit;
mod chunk_exe_rv32_commit;
mod chunk_leaf_commit;

pub mod rv32 {
    pub const EXE_COMMIT: [u32; 8] = super::chunk_exe_rv32_commit::COMMIT;
    pub const LEAF_COMMIT: [u32; 8] = super::chunk_leaf_commit::COMMIT;
}
pub mod openvm {
    pub const EXE_COMMIT: [u32; 8] = super::chunk_exe_commit::COMMIT;
    pub const LEAF_COMMIT: [u32; 8] = super::chunk_leaf_commit::COMMIT;
}
