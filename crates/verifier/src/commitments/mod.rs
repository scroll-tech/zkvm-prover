mod batch_leaf_commit;
mod batch_exe_commit;
mod chunk_exe_commit;
mod chunk_leaf_commit;
mod bundle_leaf_commit;
mod bundle_exe_commit;

pub mod batch {
    use super::batch_exe_commit;
    use super::batch_leaf_commit;

    pub const EXE_COMMIT: [u32; 8] = batch_exe_commit::COMMIT;
    pub const VM_COMMIT: [u32; 8] = batch_leaf_commit::COMMIT;
}

pub mod bundle {
    use super::bundle_exe_commit;
    use super::bundle_leaf_commit;

    pub const EXE_COMMIT: [u32; 8] = bundle_exe_commit::COMMIT;
    pub const VM_COMMIT: [u32; 8] = bundle_leaf_commit::COMMIT;
}

pub mod chunk {
    use super::chunk_exe_commit;
    use super::chunk_leaf_commit;

    pub const EXE_COMMIT: [u32; 8] = chunk_exe_commit::COMMIT;
    pub const VM_COMMIT: [u32; 8] = chunk_leaf_commit::COMMIT;
}
