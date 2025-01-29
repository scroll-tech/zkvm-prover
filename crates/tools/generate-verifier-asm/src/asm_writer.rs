use openvm_instructions::{LocalOpcode, instruction::Instruction, program::Program};
use openvm_native_compiler::NativeJalOpcode;
use openvm_stark_sdk::p3_baby_bear::BabyBear as F;

use p3_field::{FieldAlgebra, PrimeField32};

const OPCODE: u32 = 0x0b;
const FUNCT3: u32 = 0b111;
pub const LONG_FORM_INSTRUCTION_INDICATOR: u32 = (FUNCT3 << 12) + OPCODE;
pub const GAP_INDICATOR: u32 = (1 << 25) + (FUNCT3 << 12) + OPCODE;

fn u32_to_directive(x: u32) -> String {
    let opcode = x & 0b1111111;
    let funct3 = (x >> 12) & 0b111;
    let rd = (x >> 7) & 0b11111;
    let rs1 = (x >> 15) & 0b11111;
    let mut simm12 = (x >> 20) as i32;
    if simm12 >= 1 << 11 {
        simm12 -= 1 << 12;
    }
    format!(
        ".insn i {}, {}, x{}, x{}, {}",
        opcode, funct3, rd, rs1, simm12
    )
}

fn handle_pc_diff(program: &mut Program<F>) -> usize {
    let mut pc_diff = 2;
    for _op in &program.defined_instructions() {
        pc_diff += 1 + 1 + 7; // don't skip unused operands
    }
    pc_diff += 9; // for next jal
    let jal = Instruction::<F> {
        opcode: NativeJalOpcode::JAL.global_opcode(),
        a: F::from_canonical_usize(1 << (24 - 8)), // A0
        b: F::from_canonical_usize(4 * (pc_diff + 1)),
        c: F::from_canonical_usize(0),
        d: F::from_canonical_usize(5), // native_as
        e: F::from_canonical_usize(0),
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    };
    program.push_instruction(jal);
    pc_diff
}

pub fn post_process_and_write(mut program: Program<F>, path: &str) {
    let pc_diff = handle_pc_diff(&mut program);
    let assembly_and_comments = convert_program_to_u32s(&program, pc_diff);
    let mut asm_output = String::new();
    for (u32s, comment) in &assembly_and_comments {
        for (idx, x) in u32s.iter().enumerate() {
            asm_output.push_str(&u32_to_directive(*x));
            if idx == 0 {
                asm_output.push_str(" // ");
                asm_output.push_str(comment);
            }
            asm_output.push('\n');
        }
    }
    std::fs::write(path, asm_output).expect("fail to write");
}

fn convert_program_to_u32s(program: &Program<F>, pc_diff: usize) -> Vec<(Vec<u32>, String)> {
    program
        .defined_instructions()
        .iter()
        .map(|ins| {
            assert_ne!(ins.opcode.as_usize(), 259);
            (
                vec![
                    LONG_FORM_INSTRUCTION_INDICATOR,
                    7,
                    ins.opcode.as_usize() as u32,
                    ins.a.as_canonical_u32(),
                    ins.b.as_canonical_u32(),
                    ins.c.as_canonical_u32(),
                    ins.d.as_canonical_u32(),
                    ins.e.as_canonical_u32(),
                    ins.f.as_canonical_u32(),
                    ins.g.as_canonical_u32(),
                ],
                format!("{:?}", ins.opcode),
            )
        })
        .chain(std::iter::once((
            vec![GAP_INDICATOR, pc_diff as u32],
            "GAP_INDICATOR".to_string(),
        )))
        .collect()
}
