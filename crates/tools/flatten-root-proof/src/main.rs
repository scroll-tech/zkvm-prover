use openvm_sdk::{
    commit::AppExecutionCommit,
    config::{AppConfig, SdkVmConfig},
    fs::{read_app_pk_from_file, read_exe_from_file, read_root_proof_from_file},
    keygen::AppProvingKey,
    verifier::root::types::RootVmVerifierInput,
    Sdk, StdIn,
};

use openvm_native_recursion::hints::Hintable;

use openvm_stark_sdk::{
    p3_baby_bear::BabyBear as F,
    config::baby_bear_poseidon2::BabyBearPoseidon2Config
};
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;

#[derive(serde::Serialize)]
struct FlattenRootProof {
    flatten_proof: Vec<u32>,
    public_values: Vec<u32>,
}

fn flatten_root_vm_verifier_input(root_proof: &RootVmVerifierInput<BabyBearPoseidon2Config>) -> FlattenRootProof {
    let full_proof_steams = root_proof.write();

        let mut flatten_input: Vec<u32> = Vec::new();
        for x in &full_proof_steams {
            flatten_input.push(x.len() as u32);
            for f in x {
                flatten_input.push(f.as_canonical_u32());
            }
        }
        let mut public_values = vec![];
        /* 
        public_values.extend(exe_commit.map(|x| x.as_canonical_u32()));
        public_values.extend(
                leaf_commit
                .map(|x| x.as_canonical_u32()),
        );
    */
        public_values.extend(
            root_proof
                .public_values
                .iter()
                .map(|x| x.as_canonical_u32()),
        );
        FlattenRootProof {
            flatten_proof: flatten_input,
            public_values: public_values,
        }
}

/*
output will be like
raw exe commit: [396649651, 1175086036, 1682626845, 471855974, 1659938811, 1981570609, 805067545, 1640289616]
exe commit: 0x007c75be55d5e8d24557d2fc2b4a1c094fd3c027a99296dd75014c7e90e7cb9f
raw leaf commit: [505034789, 682334490, 407062982, 1227826652, 298205975, 1959777750, 1633765816, 97452666]
leaf commit: 0x000764f733c43fc78b9aa7ee26610bb86d754157eeea02e09b458c9b45fea600
 */
fn display_commitments(guest_dir: &str) {
    
        let exe = read_exe_from_file(format!("{guest_dir}/app.vmexe")).unwrap();
        let app_pk: AppProvingKey<SdkVmConfig> =
            read_app_pk_from_file(format!("{guest_dir}/app.pk")).unwrap();
        let committed_exe = Sdk
            .commit_app_exe(app_pk.app_fri_params(), exe.clone())
            .unwrap();

        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            &committed_exe,
            &app_pk.leaf_committed_exe,
        );
        println!("raw exe commit: {:?}", commits.exe_commit.map(|x| x.as_canonical_u32()));
        println!("exe commit: {:?}", commits.exe_commit_to_bn254());
        println!("raw leaf commit: {:?}", commits.leaf_vm_verifier_commit.map(|x| x.as_canonical_u32()));
        println!("leaf commit: {:?}", commits.app_config_commit_to_bn254());
        //commits
    
}

fn flatten_proof(input: &str, output: &str) {

    let proof = scroll_zkvm_prover::ChunkProof::from_json(input).unwrap();
    let root_proof = proof.proof;


        let flatten_root_proof = flatten_root_vm_verifier_input(
            &root_proof,
        );
        let flatten_proof_bytes =    bitcode::serialize(&flatten_root_proof).unwrap();
    


        std::fs::write(
            output,
            flatten_proof_bytes.clone(),
        )
        .expect("fail to write");
}

fn main() {
    // assign args[0] to input and args[1] to output
    let input = std::env::args().nth(1).expect("no input file given");
    //display_commitments(input.as_str());
    let output = std::env::args().nth(2).expect("no output file given");
    flatten_proof(&input, &output);
}
