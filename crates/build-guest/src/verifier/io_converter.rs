use openvm_instructions::{LocalOpcode, SystemOpcode, instruction::Instruction};
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
    // a useless slot. It was used to store pi_idx in native kernel
    let tmp_slot = op.c;
    let mut results = vec![
        // load [x29 + 4 * idx] to x30
        Instruction::<F> {
            opcode: Rv32LoadStoreOpcode::LOADW.global_opcode(),
            a: F::from_canonical_usize(X30 * 4),
            b: F::from_canonical_usize(X29 * 4),
            c: F::from_canonical_usize(4 * idx),
            d: as_register(),
            e: as_mem(),
            f: F::from_canonical_usize(1),
            g: F::from_canonical_usize(0),
        },
    ];
    results.extend(print_register(X30));
    results.extend(load_register_to_native(tmp_slot, X30));
    // if [A0-1] == [pi_value_addr], pc += 8
    // else, panic
    let mut bad_path = print_imm(F::from_canonical_usize(1000000));
    bad_path.extend(print_native(tmp_slot));
    bad_path.extend(print_native(pi_value_addr));
    bad_path.extend(vec![Instruction::<F> {
        opcode: SystemOpcode::TERMINATE.global_opcode(),
        a: F::from_canonical_usize(0),
        b: F::from_canonical_usize(0),
        c: F::from_canonical_usize(7), // exit code
        d: F::from_canonical_usize(0),
        e: F::from_canonical_usize(0),
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    }]);
    bad_path.extend(print_imm(F::from_canonical_usize(1234569)));

    results.extend(print_imm(F::from_canonical_usize(1234568)));
    results.extend(vec![Instruction::<F> {
        opcode: op_native_beq(),
        a: tmp_slot,
        b: pi_value_addr,
        c: F::from_canonical_usize(4 + 4 * bad_path.len()),
        d: as_native(),
        e: as_native(),
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    }]);
    results.extend(bad_path);
    results.extend(print_imm(F::from_canonical_usize(1234566)));
    results
}
