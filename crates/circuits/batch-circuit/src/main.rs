mod batch;
mod blob_data;
mod blob_consistency;
mod chunk;
mod utils;

use openvm::io;
use {
    batch::{AsLastBatchHeader, PIBuilder, MAX_AGG_CHUNKS, ArchivedBatchTask},
    chunk::ChunkInfo,
};
use rkyv::{rancor::BoxedError, access};

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm::platform as openvm_platform,
    openvm_keccak256_guest, // trigger extern native-keccak256   
};

openvm_algebra_guest::moduli_setup::moduli_init! {
    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
} 

openvm::entry!(main);

const EXE_COMMIT : [u32; 8] =[396649651, 1175086036, 1682626845, 471855974, 1659938811, 1981570609, 805067545, 1640289616];
const LEAF_COMMIT: [u32; 8] = [505034789, 682334490, 407062982, 1227826652, 298205975, 1959777750, 1633765816, 97452666];


// will terminate inside if fail
fn exec_kernel(input: &[u32], expect_output: &[u32]) {
    let mut input_ptr: *const u32 = input.as_ptr();
    let mut output_ptr: *const u32 = expect_output.as_ptr();
    let mut buf1: u32 = 0;
    let mut buf2: u32 = 0;
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    unsafe {
        std::arch::asm!(
            include_str!("../../../tools/generate-verifier-asm/root_verifier.asm"),
            inout("x28") input_ptr,
            inout("x29") output_ptr,
            inout("x30") buf1,
            inout("x31") buf2,
        )
    }
}

fn verify_chunk_proof(flatten_proof: &[u32], public_inputs: &[u32]) {
    let mut full_pi = vec![];
    let default_pi_len = 32;
    assert_eq!(default_pi_len, public_inputs.len());
    full_pi.extend(EXE_COMMIT);
    full_pi.extend(LEAF_COMMIT);
    full_pi.extend_from_slice(public_inputs);
    exec_kernel(flatten_proof, &full_pi);
    println!("verified chunk proof successfully");
}

#[derive(serde::Deserialize)]
struct FlattenRootProof {
    flatten_proof: Vec<u32>,
    public_values: Vec<u32>,
}

fn main() {
    let raw_input: Vec<u8> = openvm::io::read_vec();
    let input: FlattenRootProof = bitcode::deserialize(&raw_input).expect("decode");

    println!(
        "input.flatten_proof[..30]: {:?}",
        &input.flatten_proof[..30]
    );
    println!(
        "input.public_values[..30]: {:?}",
        &input.public_values[..30]
    );
    verify_chunk_proof(&input.flatten_proof, &input.public_values);

}

/* 
fn main() {


    let input_data = io::read_vec();


    

    let task = access::<ArchivedBatchTask, BoxedError>(&input_data).unwrap();

    let header_v3 = task.header_v3.as_ref().unwrap();
    let chunks_info : Vec<ChunkInfo> = task.chunks_info.into_iter()
        .map(|ci|ci.into()).collect();

    let _pi = PIBuilder::construct_with_header_v3::<MAX_AGG_CHUNKS>(
        AsLastBatchHeader(header_v3), 
        chunks_info.iter(), 
        &task.blob_bytes, 
        header_v3.blob_versioned_hash.into(), 
        header_v3.l1_message_popped.into(), 
        header_v3.total_l1_message_popped.into(), 
        header_v3.last_block_timestamp.into(),
    );
//    println!("data len {}", data.len());
//    process(&data).unwrap();

}
*/