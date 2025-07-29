
use sbv_primitives::B256;
use scroll_zkvm_integration::{
    ProverTester, TestTaskBuilder, testing_hardfork,
    testers::{
        load_local_task,
        bundle::{BundleProverTester, BundleTaskGenerator},
        batch::preset_batch_multiple,
    },
    utils::metadata_from_bundle_witnesses,
    //utils::{LastHeader, build_batch_task, testing_hardfork},
};
use scroll_zkvm_prover::{
    //AsRootProof, BatchProof, ChunkProof, IntoEvmProof,
    //setup::{read_app_config, read_app_exe},
    Prover, ProverConfig,
};
use scroll_zkvm_types::public_inputs::ForkName;
use std::str::FromStr;

// fn load_recent_batch_proofs() -> eyre::Result<ProofEnum> {
//     let proof_path = glob::glob("../../.output/batch-tests-*/batch/proofs/batch-*.json")?
//         .next()
//         .unwrap()?;
//     println!("proof_path: {:?}", proof_path);
//     let batch_proofs = read_json_deep::<_, ProofEnum>(&proof_path)?;

//     let task = BundleProvingTask {
//         batch_proofs: vec![batch_proof],
//         bundle_info: None,
//         fork_name: testing_hardfork().to_string(),
//     };
//     Ok(task)
// }

fn preset_bundle() -> BundleTaskGenerator {
    BundleTaskGenerator::from_batch_tasks(&preset_batch_multiple())
}

#[test]
fn print_vks() -> eyre::Result<()> {
    #[derive(Default, Debug, serde::Serialize)]
    struct VKDump {
        pub chunk_vk: String,
        pub batch_vk: String,
        pub bundle_vk: String,
    }
    let [chunk_vk, batch_vk, bundle_vk] = ["chunk", "batch", "bundle"].map(|circuit| {
        let dev_mode = true;
        let (path_app_exe, path_app_config) = if dev_mode {
            (
                format!("../../crates/circuits/{circuit}-circuit/openvm/app.vmexe").into(),
                format!("../../crates/circuits/{circuit}-circuit/openvm.toml").into(),
            )
        } else {
            let version = "0.5.0";
            (
                format!("../../{version}/{circuit}/app.vmexe").into(),
                format!("../../{version}/{circuit}/openvm.toml").into(),
            )
        };

        let config = ProverConfig {
            path_app_exe,
            path_app_config,
            ..Default::default()
        };

        use base64::{Engine, prelude::BASE64_STANDARD};
        let app_vk = BASE64_STANDARD.encode(Prover::setup(config, false, None).unwrap().get_app_vk());
        println!("{circuit}: {app_vk}");
        app_vk
    });

    let dump = VKDump {
        chunk_vk,
        batch_vk,
        bundle_vk,
    };

    let f = std::fs::File::create("openVmVk.json")?;
    serde_json::to_writer(f, &dump)?;
    Ok(())
}

// #[test]
// fn setup_prove_verify() -> eyre::Result<()> {
//     BundleProverTester::setup()?;

//     let task = load_recent_batch_proofs()?;
//     prove_verify_single_evm::<BundleProverTester>(Some(task))?;

//     Ok(())
// }

#[ignore = "need local stuff"]
#[test]
fn setup_prove_verify_local_task() -> eyre::Result<()> {
    BundleProverTester::setup()?;
    let u_task = load_local_task("bundle-task.json")?;
    let prover = BundleProverTester::load_prover(true)?;

    let _ = prover.gen_proof_universal(&u_task, true)?;

    Ok(())
}

#[test]
fn verify_bundle_info_pi() {
    use scroll_zkvm_types::bundle::BundleInfo;

    let info = BundleInfo {
        chain_id: 534352,
        msg_queue_hash: Default::default(),
        num_batches: 12,
        prev_state_root: B256::from_str(
            "0x0090ecc1308e0033e8cfef3b6aabe1de0a93361a14075cf6246e002e62944fa3",
        )
        .unwrap(),
        prev_batch_hash: B256::from_str(
            "0x6f8315e6c702a9ea8f83fb46d2a4a8e4a01d46a5bf72de7fac179f373cf27d68",
        )
        .unwrap(),
        post_state_root: B256::from_str(
            "0x0e9c09b32fd71c248df1dbc2b8fcbf69839257296f447deb6a8f8f49b9e158e4",
        )
        .unwrap(),
        batch_hash: B256::from_str(
            "0x1655c7521aa3045f5267ff8c6b21f9ad42024f79369c447500fd04c1077c2ad5",
        )
        .unwrap(),
        withdraw_root: B256::from_str(
            "0x97f9728ad48ff896b4272abcecd9a6a46577c24fbf2504f5ed2c3178c857263a",
        )
        .unwrap(),
    };

    assert_eq!(
        info.pi_hash_euclidv1(),
        B256::from_str("0x5e49fc59ce02b42a2f693c738c582b36bd08e9cfe3acb8cee299216743869bd4")
            .unwrap()
    );
}

#[test]
fn e2e() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let task = preset_bundle();
    let wit = task.gen_proving_witnesses()?;
    let metadata = metadata_from_bundle_witnesses(&wit)?;

    // Sanity check for pi of bundle hash, update the expected hash if block witness changed
    let pi_str = match testing_hardfork() {
        ForkName::EuclidV1 => "3cc70faf6b5a4bd565694a4c64de59befb735f4aac2a4b9e6a6fc2ee950b8a72",
        ForkName::EuclidV2 => "2028510c403837c6ed77660fd92814ba61d7b746e7268cc8dfc14d163d45e6bd",
        ForkName::Feynman => "80523a61b2b94b2922638ec90edd084b1022798e1e5539c3a079d2b0736e4f32",
    };
    let expected_pi_hash = metadata.pi_hash(testing_hardfork());
    // sanity check for pi of bundle hash, update the expected hash if block witness changed
    assert_eq!(
        alloy_primitives::hex::encode(expected_pi_hash),
        pi_str,
        "unexpected pi hash for e2e bundle info, block witness changed?"
    );    

    let prover = BundleProverTester::load_prover(true)?;
    let proof = task.gen_witnesses_proof(&prover)?;


    let evm_proof = proof.into_evm_proof().unwrap();

    // assert!(
    //     verifier
    //         .to_bundle_verifier_v2()
    //         .verify_proof_evm(&evm_proof)
    // );

    let observed_instances = &evm_proof.instances;

    for (i, (&expected, &observed)) in expected_pi_hash
        .iter()
        .zip(observed_instances.iter().skip(14).take(32))
        .enumerate()
    {
        assert_eq!(
            expected,
            observed,
            "pi inconsistent at index {i}: expected={expected}, observed={observed:?}"
        );
    }

    Ok(())

}
