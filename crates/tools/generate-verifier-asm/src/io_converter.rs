use openvm_instructions::{LocalOpcode, SystemOpcode, instruction::Instruction};
use openvm_native_compiler::{CastfOpcode, NativeLoadStoreOpcode, asm::A0};
use openvm_rv32im_transpiler::{BaseAluOpcode, Rv32LoadStoreOpcode};
use openvm_stark_sdk::p3_baby_bear::BabyBear as F;
use p3_field::{FieldAlgebra, PrimeField32};

use crate::asm_utils::*;

//////////////// convert `hint_read`` and `publish` ///////////////////

pub fn convert_hintread(op: Instruction<F>) -> Vec<Instruction<F>> {
    // x28
    // x30: value

    let native_addr = op.c.as_canonical_u32() as usize;
    let offset = op.b.as_canonical_u32() as usize;
    let tmp_slot = A0 - 4;
    // VmOpcode(260) 0 0 16777150 5 5 0 0    // StoreHintWord
    vec![Instruction::<F> {
        opcode: Rv32LoadStoreOpcode::LOADW.global_opcode(),
        a: F::from_canonical_usize(X30 * 4),
        b: F::from_canonical_usize(X28 * 4),
        c: F::from_canonical_usize(0),
        d: as_register(),
        e: as_mem(),
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    }]
    .into_iter()
    .chain(load_register_to_native(tmp_slot as usize, X30))
    .chain(vec![
        Instruction::<F> {
            opcode: NativeLoadStoreOpcode::STOREW.global_opcode(),
            a: F::from_canonical_usize(tmp_slot as usize),
            b: F::from_canonical_usize(offset),
            c: F::from_canonical_usize(native_addr),
            d: as_native(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X28 * 4),
            b: F::from_canonical_usize(X28 * 4),
            c: F::from_canonical_usize(4),
            d: as_register(),
            e: as_imm(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ])
    .collect::<Vec<_>>()
}

pub fn convert_publish(op: Instruction<F>) -> Vec<Instruction<F>> {
    // register usage:
    //   x29: ptr of pi
    //   x31: local tmp, for current pi ptr
    //   x30: local tmp, for current pi value
    // step1: x31 = x29 + 4 * pi.index
    // step2: load [x31] to x30 (it is the expected value)
    // step3: load_register_to_native(x30, A0-1)
    // step4: if [A0-1] != [pi_value_addr], fail
    let pi_value_addr = op.b;
    let pi_idx_addr = op.c;
    let tmp_slot = A0 - 4;
    let mut results = vec![
        // castf pi_idx to x31
        Instruction::<F> {
            opcode: CastfOpcode::CASTF.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: pi_idx_addr,
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        // x31 *= 2
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        // x31 *= 2
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        // x31 += x29
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X29 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        // load [x31] to x30
        Instruction::<F> {
            opcode: Rv32LoadStoreOpcode::LOADW.global_opcode(),
            a: F::from_canonical_usize(X30 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(0),
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
        // Instruction::phantom(
        // PhantomDiscriminant(SysPhantom::DebugPanic as u16),
        // F::ZERO,
        // F::ZERO,
        // 0,
        // )
    ]);
    results
}

#[allow(dead_code)]
pub fn convert_publish_old(op: Instruction<F>) -> Vec<Instruction<F>> {
    // this is the depreciated method.
    // I tried to copy the native field to main memory.
    // but found `castf` (due to range check limitation) is not working
    // step1: castf the field to x30 (not work!)
    // step2: x31 = x29 + 4 * pi.index
    // step3: storew x30 to x31

    // example instruction: VmOpcode(288) 0 16776149 16776511 0 5 5 0
    let pi_value_addr = op.b;
    let pi_idx_addr = op.c;

    // x29: output, const
    // x30: the pi value | hint value
    // x31: the pi index
    vec![
        Instruction::<F> {
            opcode: CastfOpcode::CASTF.global_opcode(),
            a: F::from_canonical_usize(X30 * 4),
            b: pi_value_addr,
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: CastfOpcode::CASTF.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: pi_idx_addr,
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        // we need x31*=4
        // here i add itself twice
        // TODO: shift left by 2 bits?
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: BaseAluOpcode::ADD.global_opcode(),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X29 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: Rv32LoadStoreOpcode::STOREW.global_opcode(),
            a: F::from_canonical_usize(X30 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_mem(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ]
}
