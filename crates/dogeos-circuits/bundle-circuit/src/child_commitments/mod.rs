mod batch_exe_commit;
mod batch_vm_commit;
pub const EXE_COMMIT: [u32; 8] = batch_exe_commit::COMMIT;
pub const VM_COMMIT: [u32; 8] = batch_vm_commit::COMMIT;
