use openvm_sdk::commit::AppExecutionCommit;
use sbv_primitives::B256;
use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single_evm,
    testers::{
        batch::BatchProverTester,
        bundle::{BundleLocalTaskTester, BundleProverTester},
        chunk::MultiChunkProverTester,
    },
    utils::{LastHeader, build_batch_task, testing_hardfork},
};
use scroll_zkvm_prover::{
    AsRootProof, BatchProof, ChunkProof, IntoEvmProof,
    setup::{read_app_config, read_app_exe},
    task::{bundle::BundleProvingTask, chunk::ChunkProvingTask},
    utils::{read_json_deep, write_json},
};
use scroll_zkvm_types::public_inputs::ForkName;
use std::str::FromStr;

fn load_recent_batch_proofs() -> eyre::Result<BundleProvingTask> {
    let proof_path = glob::glob("../../.output/batch-tests-*/batch/proofs/batch-*.json")?
        .next()
        .unwrap()?;
    println!("proof_path: {:?}", proof_path);
    let batch_proof = read_json_deep::<_, BatchProof>(&proof_path)?;

    let task = BundleProvingTask {
        batch_proofs: vec![batch_proof],
        bundle_info: None,
        fork_name: testing_hardfork().to_string(),
    };
    Ok(task)
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

        let config = scroll_zkvm_prover::ProverConfig {
            path_app_exe,
            path_app_config,
            ..Default::default()
        };

        let app_exe = read_app_exe(&config.path_app_exe).unwrap();
        let app_config = read_app_config(&config.path_app_config).unwrap();
        let sdk = openvm_sdk::Sdk::new();
        let app_pk = sdk.app_keygen(app_config).unwrap();
        let app_committed_exe = sdk
            .commit_app_exe(app_pk.app_fri_params(), app_exe)
            .unwrap();
        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            &app_committed_exe,
            &app_pk.leaf_committed_exe,
        );

        let exe = commits.app_exe_commit.to_u32_digest();
        let leaf = commits.app_vm_commit.to_u32_digest();

        let app_vk = scroll_zkvm_types::types_agg::ProgramCommitment { exe, leaf }.serialize();

        use base64::{Engine, prelude::BASE64_STANDARD};
        let app_vk = BASE64_STANDARD.encode(app_vk);
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

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let task = load_recent_batch_proofs()?;
    prove_verify_single_evm::<BundleProverTester>(Some(task))?;

    Ok(())
}

#[test]
fn setup_prove_verify_local_task() -> eyre::Result<()> {
    BundleLocalTaskTester::setup()?;
    prove_verify_single_evm::<BundleLocalTaskTester>(None)?;

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

fn build_chunk_outcome() -> eyre::Result<(Vec<ChunkProvingTask>, Vec<ChunkProof>)> {
    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    Ok((outcome.tasks, outcome.proofs))
}

#[test]
fn e2e() -> eyre::Result<()> {
    BundleProverTester::setup()?;

    let (chunk_tasks, chunk_proofs) = build_chunk_outcome()?;
    assert_eq!(chunk_tasks.len(), chunk_proofs.len());
    assert_eq!(chunk_tasks.len(), 3);

    // Construct batch tasks using chunk tasks and chunk proofs.
    let batch_task_1 =
        build_batch_task(&chunk_tasks[0..1], &chunk_proofs[0..1], Default::default());
    let batch_task_2 = build_batch_task(
        &chunk_tasks[1..],
        &chunk_proofs[1..],
        LastHeader::from(&batch_task_1.batch_header),
    );
    let batch_task_example = batch_task_1.clone();

    let outcome = prove_verify_multi::<BatchProverTester>(Some(&[batch_task_1, batch_task_2]))?;

    let fork_name = testing_hardfork().to_string();
    // Construct bundle task using batch tasks and batch proofs.
    let bundle_task = BundleProvingTask {
        batch_proofs: outcome.proofs,
        bundle_info: None,
        fork_name: fork_name.clone(),
    };
    let (outcome, verifier, path_assets) =
        prove_verify_single_evm::<BundleProverTester>(Some(bundle_task.clone()))?;

    assert_eq!(outcome.proofs.len(), 1, "single bundle proof");

    let bundle_task_with_info = BundleProvingTask {
        batch_proofs: outcome.tasks[0].batch_proofs.clone(),
        bundle_info: Some(outcome.proofs[0].metadata.bundle_info.clone()),
        fork_name,
    };
    // collect batch and bundle task as data example
    write_json(path_assets.join("batch-task.json"), &batch_task_example)?;
    write_json(path_assets.join("bundle-task.json"), &bundle_task_with_info)?;

    // Verifier all above proofs with the verifier-only mode.
    let verifier = verifier.to_chunk_verifier();
    for proof in chunk_proofs.iter() {
        assert!(verifier.verify_proof(proof.as_root_proof()));
    }
    let verifier = verifier.to_batch_verifier();
    for proof in bundle_task.batch_proofs.iter() {
        assert!(verifier.verify_proof(proof.as_root_proof()));
    }

    let evm_proof = outcome.proofs[0].clone().into_evm_proof();

    assert!(
        verifier
            .to_bundle_verifier_v2()
            .verify_proof_evm(&evm_proof)
    );

    let expected_pi_hash = &outcome.proofs[0].metadata.bundle_pi_hash;
    let observed_instances = &evm_proof.user_public_values;

    for (i, (&expected, &observed)) in expected_pi_hash
        .iter()
        .zip(observed_instances.iter())
        .enumerate()
    {
        assert_eq!(
            expected,
            observed,
            "pi inconsistent at index {i}: expected={expected}, observed={observed:?}"
        );
    }

    // Sanity check for pi of bundle hash, update the expected hash if block witness changed
    let pi_str = match testing_hardfork() {
        ForkName::EuclidV1 => "3cc70faf6b5a4bd565694a4c64de59befb735f4aac2a4b9e6a6fc2ee950b8a72",
        ForkName::EuclidV2 => "2028510c403837c6ed77660fd92814ba61d7b746e7268cc8dfc14d163d45e6bd",
        ForkName::Feynman => "80523a61b2b94b2922638ec90edd084b1022798e1e5539c3a079d2b0736e4f32",
    };
    // sanity check for pi of bundle hash, update the expected hash if block witness changed
    assert_eq!(
        alloy_primitives::hex::encode(expected_pi_hash),
        pi_str,
        "unexpected pi hash for e2e bundle info, block witness changed?"
    );

    Ok(())
}
