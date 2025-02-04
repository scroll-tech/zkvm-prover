use openvm_sdk::{
    commit::AppExecutionCommit, config::{AppConfig, SdkVmConfig}, fs::{read_exe_from_file}, Sdk
};
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::PrimeField32,
};

// output will be like
// raw exe commit: [396649651, 1175086036, 1682626845, 471855974, 1659938811, 1981570609, 805067545, 1640289616]
// exe commit: 0x007c75be55d5e8d24557d2fc2b4a1c094fd3c027a99296dd75014c7e90e7cb9f
// raw leaf commit: [505034789, 682334490, 407062982, 1227826652, 298205975, 1959777750, 1633765816, 97452666]
// leaf commit: 0x000764f733c43fc78b9aa7ee26610bb86d754157eeea02e09b458c9b45fea600
fn display_commitments(guest_dir: &str) {
    println!("000");
    let exe = read_exe_from_file(format!("{guest_dir}/app.vmexe")).unwrap();

    println!("001");
    let toml = std::fs::read_to_string(format!("{guest_dir}/openvm.toml")).unwrap();
    let app_config: AppConfig<SdkVmConfig> = toml::from_str(&toml).unwrap();
    println!("002");
    let app_pk = Sdk.app_keygen(app_config).unwrap();
    println!("0025");
    let committed_exe = Sdk
        .commit_app_exe(app_pk.app_fri_params(), exe.clone())
        .unwrap();

        println!("003");
    let commits = AppExecutionCommit::compute(
        &app_pk.app_vm_pk.vm_config,
        &committed_exe,
        &app_pk.leaf_committed_exe,
    );
    println!(
        "raw exe commit: {:?}",
        commits.exe_commit.map(|x| x.as_canonical_u32())
    );
    println!("exe commit: {:?}", commits.exe_commit_to_bn254());
    println!(
        "raw leaf commit: {:?}",
        commits
            .leaf_vm_verifier_commit
            .map(|x| x.as_canonical_u32())
    );
    println!("leaf commit: {:?}", commits.app_config_commit_to_bn254());
}

fn main() {
    let guest_dir = std::env::args().nth(1).expect("no input file given");
    display_commitments(guest_dir.as_str());
}
