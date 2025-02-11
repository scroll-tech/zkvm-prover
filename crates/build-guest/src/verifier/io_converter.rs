use openvm_instructions::{LocalOpcode, SystemOpcode, instruction::Instruction};
use openvm_native_compiler::asm::A0;
use openvm_rv32im_transpiler::Rv32LoadStoreOpcode;
use openvm_stark_sdk::p3_baby_bear::BabyBear as F;
use p3_field::FieldAlgebra;

use super::asm_utils::*;

// This function assumes the pi is published in sequencial order
// `convert_publish_v1` was a more general version, but now `castf` cannot write to register,
// so I have to use the `idx` here.
pub fn convert_publish(op: Instruction<F>, idx: usize) -> Vec<Instruction<F>> {
    // register usage:
    //   x29: ptr of pi
    //   x30: local tmp, for current pi value
    // step1: load [x29 + 4 * idx] to x30 (it is the expected value)
    // step2: load_register_to_native(x30, A0-1)
    // step3: if [A0-1] != [pi_value_addr], fail
    let pi_value_addr = op.b;
    let tmp_slot = A0 - 4;
    let mut results = vec![
        // load [x29 + 4 * idx] to x30
        Instruction::<F> {
            opcode: Rv32LoadStoreOpcode::LOADW.global_opcode(),
            a: F::from_canonical_usize(X30 * 4),
            b: F::from_canonical_usize(X29 * 4),
            c: F::from_canonical_usize(4 * idx),
            d: as_register(),
            e: as_mem(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ];
    results.extend(load_register_to_native(tmp_slot as usize, X30));
    // if [A0-1] == [pi_value_addr], pc += 8
    // else, panic
    results.extend(vec![
        Instruction::<F> {
            opcode: op_native_beq(),
            a: F::from_canonical_usize(tmp_slot as usize),
            b: pi_value_addr,
            c: F::from_canonical_usize(8),
            d: as_native(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: SystemOpcode::TERMINATE.global_opcode(),
            a: F::from_canonical_usize(0),
            b: F::from_canonical_usize(0),
            c: F::from_canonical_usize(8),
            d: F::from_canonical_usize(0),
            e: F::from_canonical_usize(0),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ]);
    results
}
