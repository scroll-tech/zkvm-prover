use openvm_instructions::{
    LocalOpcode, PublishOpcode, SystemOpcode,
    SystemOpcode::PHANTOM,
    instruction::{DebugInfo, Instruction},
    program::Program,
};
use openvm_native_compiler::{NativeJalOpcode, NativeLoadStoreOpcode, NativePhantom};
use openvm_sdk::{config::AggStarkConfig, keygen::AggStarkProvingKey};
use openvm_stark_sdk::p3_baby_bear::BabyBear as F;
use p3_field::{FieldAlgebra, PrimeField32};

mod asm_utils;
use asm_utils::*;
mod io_converter;
use io_converter::*;
mod asm_writer;
use asm_writer::*;

// VmOpcode(1) 0 0 17 0 0 0 0    // HintInputVec
// VmOpcode(260) 0 0 16777150 5 5 0 0    // StoreHintWord
// VmOpcode(256) 16777143 0 16777150 5 5 0 0    // LoadV

fn load_root_program(agg_stark_pk: &AggStarkProvingKey) -> Program<F> {
    // load from root_exe.bin if exist, otherwise load from pk
    let root_exe = {
        let root_exe = &agg_stark_pk.root_verifier_pk.root_committed_exe;
        let root_exe = &root_exe.exe;
        root_exe.clone()
    };

    // println!("root program: {}", root_program.program);
    let program = root_exe.program.clone();
    println!(
        "total ins count: {}, {}",
        program.instructions_and_debug_infos.len(),
        program.defined_instructions().len(),
    );
    program
}

fn op_publish() -> usize {
    PublishOpcode::PUBLISH.global_opcode().as_usize()
}

fn op_hintstore() -> usize {
    NativeLoadStoreOpcode::HINT_STOREW
        .global_opcode()
        .as_usize()
}

fn op_phantom() -> usize {
    PHANTOM.global_opcode().as_usize()
}

fn op_jal() -> usize {
    NativeJalOpcode::JAL.global_opcode().as_usize()
}

#[derive(Debug, Default)]
struct Context {
    hint_bits_mode: bool,
    hint_bits_counter: usize,
    hint_bits_counter_limit: usize,
    publish_counter: usize,
}

impl Context {
    fn hint_bits_mode(&self) -> bool {
        self.hint_bits_mode
    }
    fn reset(&mut self) {
        self.hint_bits_mode = false;
        self.hint_bits_counter = 0;
        self.hint_bits_counter_limit = 0;
    }
    fn inc(&mut self) {
        self.hint_bits_counter += 1;
        if self.hint_bits_counter >= self.hint_bits_counter_limit {
            self.reset();
        }
    }
    fn enable_hint_bits_mode(&mut self, limit: usize) {
        self.hint_bits_mode = true;
        self.hint_bits_counter = 0;
        self.hint_bits_counter_limit = limit;
    }
}

// Alias for convenience.
type InstructionsWithDbgInfo = Vec<(Option<(Instruction<F>, Option<DebugInfo>)>, usize)>;

fn dump_root_program(stark_pk: &AggStarkProvingKey, output_file: &str) {
    let mut program = load_root_program(stark_pk);

    let mut new_instructions_and_debug_infos: InstructionsWithDbgInfo = vec![];
    let mut context = Context::default();
    for (idx, op_elem) in program.instructions_and_debug_infos.iter().enumerate() {
        if let Some(op) = op_elem.as_ref() {
            if op.0.opcode.as_usize() == op_publish() {
                let instructions = convert_publish(op.0.clone(), context.publish_counter);
                context.publish_counter += 1;
                new_instructions_and_debug_infos.extend(
                    instructions
                        .iter()
                        .map(|x| (Some((x.clone(), None)), idx * 4)),
                );
                continue;
            }
            if op.0.opcode.as_usize() == op_phantom() {
                if op.0.c.as_canonical_u32() as usize == NativePhantom::HintInput as usize {
                    // nop
                    let instructions = [Instruction {
                        opcode: SystemOpcode::PHANTOM.global_opcode(),
                        ..Default::default()
                    }];
                    new_instructions_and_debug_infos.extend(
                        instructions
                            .iter()
                            .map(|x| (Some((x.clone(), None)), idx * 4)),
                    );
                    continue;
                }
                if op.0.c.as_canonical_u32() as usize
                    == (AS_NATIVE << 16 | (NativePhantom::HintBits as usize))
                {
                    context.enable_hint_bits_mode(op.0.b.as_canonical_u32() as usize);
                    new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
                    continue;
                }
            }
            if op.0.opcode.as_usize() == op_hintstore() {
                if context.hint_bits_mode() {
                    new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
                    context.inc();
                    continue;
                } else {
                    let instructions = convert_hintread(op.0.clone());
                    new_instructions_and_debug_infos.extend(
                        instructions
                            .iter()
                            .map(|x| (Some((x.clone(), None)), idx * 4)),
                    );
                    continue;
                }
            }
        };
        new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
    }

    fix_pc(&mut new_instructions_and_debug_infos);

    program.instructions_and_debug_infos = new_instructions_and_debug_infos
        .into_iter()
        .map(|x| x.0)
        .collect();

    if let Some(0) = program
        .instructions_and_debug_infos
        .last()
        .unwrap()
        .as_ref()
        .map(|x| x.0.opcode.as_usize())
    {
        program.instructions_and_debug_infos.pop();
    }

    post_process_and_write(program, output_file);
    println!("written to {}", output_file);
}

fn fix_pc(new_instructions_and_debug_infos: &mut InstructionsWithDbgInfo) {
    // fix jump and pc
    // step1: for all jal, collect the old_pc=>new_pc mapping

    // idx=>correct pc
    let mut pc_rewrite = vec![];
    for (idx, op_elem) in new_instructions_and_debug_infos.iter().enumerate() {
        if let Some(op) = &op_elem.0 {
            if op.0.opcode.as_usize() == op_jal()
                || op.0.opcode.as_usize() == op_native_beq().as_usize()
                || op.0.opcode.as_usize() == op_native_bne().as_usize()
            {
                let old_pc_diff = if op.0.opcode.as_usize() == op_jal() {
                    op.0.b.as_canonical_u32() as usize
                } else {
                    op.0.c.as_canonical_u32() as usize
                };
                // special case for our 'beq' inside `publish` transpiling
                if old_pc_diff == 8 {
                    if let (Some((op, _)), _) = &new_instructions_and_debug_infos[idx + 1] {
                        if op.opcode.as_usize() == op_halt().as_usize() {
                            continue;
                        }
                    }
                }
                let babybear = F::ORDER_U32 as usize;
                let old_pc_target = (op_elem.1 + old_pc_diff) % babybear;
                // println!("old pc: {}", old_pc);
                // find the idx of new_instructions_and_debug_infos where element.1 == old_pc
                let new_idx = new_instructions_and_debug_infos
                    .iter()
                    .enumerate()
                    .find(|(_, x)| x.1 == old_pc_target)
                    .map(|x| x.0);
                // if !new_pc.map(|x| x == old_pc).unwrap_or(false) {
                //    println!("WARN: new pc == old pc {}", old_pc);
                //}
                match new_idx {
                    Some(new_idx) => {
                        let new_pc = new_idx * 4;
                        let new_pc_diff = (new_pc + babybear - idx * 4) % babybear;
                        if new_pc_diff != old_pc_diff {
                            pc_rewrite.push((
                                idx,
                                new_pc_diff,
                                if op.0.opcode.as_usize() == op_jal() {
                                    1 // b
                                } else {
                                    2 // c
                                },
                            ));
                        }
                    }
                    None => {
                        println!("WARN: fail to find new pc for old pc {}", old_pc_target);
                    }
                }
            }
        }
    }
    for (idx, new_pc_diff, op_idx) in pc_rewrite {
        if op_idx == 1 {
            new_instructions_and_debug_infos[idx]
                .0
                .as_mut()
                .unwrap()
                .0
                .b = F::from_canonical_usize(new_pc_diff);
        } else if op_idx == 2 {
            new_instructions_and_debug_infos[idx]
                .0
                .as_mut()
                .unwrap()
                .0
                .c = F::from_canonical_usize(new_pc_diff);
        } else {
            panic!("invalid op_idx");
        }
    }
}

fn main() {
    println!("generating AggStarkProvingKey");
    let (agg_stark_pk, _) = AggStarkProvingKey::dummy_proof_and_keygen(AggStarkConfig::default());

    println!("generating root_verifier.asm");
    dump_root_program(&agg_stark_pk, "root_verifier.asm");
}
