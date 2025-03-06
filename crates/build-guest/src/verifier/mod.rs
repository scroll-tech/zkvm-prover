use openvm_instructions::{
    instruction::{DebugInfo, Instruction},
    program::Program,
};
use openvm_sdk::{config::AggStarkConfig, keygen::AggStarkProvingKey};
use openvm_stark_sdk::{config::FriParameters, p3_baby_bear::BabyBear as F};

#[allow(dead_code)]
mod asm_utils;
use asm_utils::*;
mod io_converter;
use io_converter::*;
mod asm_writer;
use asm_writer::*;

fn load_root_program(agg_stark_pk: &AggStarkProvingKey) -> Program<F> {
    let root_exe = {
        let root_exe = &agg_stark_pk.root_verifier_pk.root_committed_exe;
        let root_exe = &root_exe.exe;
        root_exe.clone()
    };

    // println!("root program: {}", root_program.program);
    let program = root_exe.program.clone();
    println!(
        "total instructions count: {}, {}",
        program.instructions_and_debug_infos.len(),
        program.defined_instructions().len(),
    );
    program
}

// Alias for convenience.
type InstructionsWithDbgInfo = Vec<Option<(Instruction<F>, Option<DebugInfo>)>>;

fn dump_root_program(stark_pk: &AggStarkProvingKey, output_file: &str) {
    let mut program = load_root_program(stark_pk);

    let mut new_instructions_and_debug_infos: InstructionsWithDbgInfo = vec![];
    let mut publish_counter: usize = 0;
    for op_elem in program.instructions_and_debug_infos.iter() {
        if let Some(op) = op_elem.as_ref() {
            if op.0.opcode.as_usize() == op_publish() {
                let instructions = convert_publish(op.0.clone(), publish_counter);
                publish_counter += 1;
                new_instructions_and_debug_infos
                    .extend(instructions.iter().map(|x| Some((x.clone(), None))));
                continue;
            }
        };
        new_instructions_and_debug_infos.push(op_elem.clone());
    }

    program.instructions_and_debug_infos = new_instructions_and_debug_infos;

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

pub fn dump_verifier(path: &str) {
    println!("generating AggStarkProvingKey");
    let mut agg_stark_config = AggStarkConfig::default();
    // always set leaf fri params's log blowup to be 1
    agg_stark_config.leaf_fri_params = FriParameters::standard_with_100_bits_conjectured_security(1);
    let (agg_stark_pk, _) = AggStarkProvingKey::dummy_proof_and_keygen(agg_stark_config);

    println!("generating root_verifier.asm");
    dump_root_program(&agg_stark_pk, path);
}
