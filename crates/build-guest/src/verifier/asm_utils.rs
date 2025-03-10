use openvm_instructions::{
    LocalOpcode, PhantomDiscriminant, PublishOpcode, SystemOpcode, SystemOpcode::PHANTOM, VmOpcode,
    instruction::Instruction,
};
use openvm_native_compiler::{
    FieldArithmeticOpcode, NativeBranchEqualOpcode, NativeJalOpcode, NativeLoadStoreOpcode,
    NativePhantom, conversion::AS,
};
use openvm_rv32im_transpiler::BranchEqualOpcode;
use openvm_stark_sdk::p3_baby_bear::BabyBear as F;

use p3_field::FieldAlgebra;

////////////////// constants //////////////////////////////

pub const X0: usize = 0; // x0
pub const X10: usize = 10; // a0
pub const X29: usize = 29; // t4
pub const X30: usize = 30; // t5

pub const AS_IMM: usize = AS::Immediate as usize;
pub const AS_REGISTER: usize = 1; //AS::REGISTER;
pub const AS_MEM: usize = 2; //AS::MEM;
pub const AS_NATIVE: usize = AS::Native as usize;

pub fn as_imm() -> F {
    F::from_canonical_usize(AS_IMM)
}
pub fn as_native() -> F {
    F::from_canonical_usize(AS_NATIVE)
}
pub fn as_register() -> F {
    F::from_canonical_usize(AS_REGISTER)
}
pub fn as_mem() -> F {
    F::from_canonical_usize(AS_MEM)
}

pub fn op_native_add() -> VmOpcode {
    FieldArithmeticOpcode::ADD.global_opcode()
}

pub fn op_native_mul() -> VmOpcode {
    FieldArithmeticOpcode::MUL.global_opcode()
}

pub fn op_native_beq() -> VmOpcode {
    NativeBranchEqualOpcode(BranchEqualOpcode::BEQ).global_opcode()
}

pub fn op_native_bne() -> VmOpcode {
    NativeBranchEqualOpcode(BranchEqualOpcode::BNE).global_opcode()
}

pub fn op_halt() -> VmOpcode {
    SystemOpcode::TERMINATE.global_opcode()
}

pub fn op_publish() -> usize {
    PublishOpcode::PUBLISH.global_opcode().as_usize()
}

pub fn op_hintstore() -> usize {
    NativeLoadStoreOpcode::HINT_STOREW
        .global_opcode()
        .as_usize()
}

pub fn op_phantom() -> usize {
    PHANTOM.global_opcode().as_usize()
}

pub fn op_jal() -> usize {
    NativeJalOpcode::JAL.global_opcode().as_usize()
}

/////////////////// debug //////////////////////////

pub fn print_native(mem_addr: F) -> Vec<Instruction<F>> {
    vec![Instruction::<F>::phantom(
        PhantomDiscriminant(NativePhantom::Print as u16),
        mem_addr,
        F::from_canonical_usize(0),
        AS_NATIVE as u16,
    )]
}

pub fn print_mem(mem_addr: F) -> Vec<Instruction<F>> {
    vec![Instruction::<F>::phantom(
        PhantomDiscriminant(NativePhantom::Print as u16),
        mem_addr,
        F::from_canonical_usize(0),
        AS_MEM as u16,
    )]
}

pub fn print_register(register_idx: usize) -> Vec<Instruction<F>> {
    [0, 1, 2, 3]
        .map(|idx| {
            Instruction::<F>::phantom(
                PhantomDiscriminant(NativePhantom::Print as u16),
                F::from_canonical_usize(4 * register_idx + idx),
                F::from_canonical_usize(0),
                AS_REGISTER as u16,
            )
        })
        .to_vec()
}

//////////////////// load and store //////////////////////////

pub fn load_register_to_native(dst: F, register_idx: usize) -> Vec<Instruction<F>> {
    let zero = F::ZERO;

    let add_op = |(b, as_b), (c, as_c)| Instruction::<F> {
        opcode: op_native_add(),
        a: dst,
        b,
        c: F::from_canonical_usize(c),
        d: as_native(),
        e: as_b,
        f: as_c,
        g: F::from_canonical_usize(0),
    };
    let shift_op = || Instruction::<F> {
        opcode: op_native_mul(),
        a: dst,
        b: dst,
        c: F::from_canonical_usize(256),
        d: as_native(),
        e: as_native(),
        f: as_imm(),
        g: F::from_canonical_usize(0),
    };
    vec![
        add_op((zero, as_imm()), (4 * register_idx + 3, as_register())),
        shift_op(),
        add_op((dst, as_native()), (4 * register_idx + 2, as_register())),
        shift_op(),
        add_op((dst, as_native()), (4 * register_idx + 1, as_register())),
        shift_op(),
        add_op((dst, as_native()), (4 * register_idx, as_register())),
    ]
}
