mod chunk_exe_commit;
mod chunk_vm_commit;

pub const EXE_COMMIT: [u32; 8] = chunk_exe_commit::COMMIT;
pub const VM_COMMIT: [u32; 8] = chunk_vm_commit::COMMIT;
