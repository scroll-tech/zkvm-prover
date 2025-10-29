use sbv_primitives::B256;
use scroll_zkvm_integration::{
    ProverTester,
    testers::{
        batch::{BatchProverTester, preset_batch_multiple, preset_batch_validium},
        bundle::{BundleProverTester, BundleTaskGenerator},
        chunk::ChunkProverTester,
        load_local_task,
    },
    testing_hardfork, testing_version_validium,
    utils::metadata_from_bundle_witnesses,
};
use scroll_zkvm_prover::{Prover, ProverConfig};
use scroll_zkvm_types::{
    proof::OpenVmEvmProof,
    public_inputs::{ForkName, MultiVersionPublicInputs},
};
use std::str::FromStr;

fn preset_bundle() -> BundleTaskGenerator {
    BundleTaskGenerator::from_batch_tasks(&preset_batch_multiple())
}

fn preset_bundle_validium() -> BundleTaskGenerator {
    BundleTaskGenerator::from_batch_tasks(&preset_batch_validium())
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

        let app_vk = hex::encode(Prover::setup(config, None).unwrap().get_app_vk());
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

#[ignore = "need local stuff"]
#[test]
fn setup_prove_verify_local_task() -> eyre::Result<()> {
    BundleProverTester::setup(true)?;
    let u_task = load_local_task("bundle-task.json")?;
    let mut prover = BundleProverTester::load_prover(true)?;

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
        encryption_key: None,
    };

    assert_eq!(
        info.pi_hash_euclidv1(),
        B256::from_str("0x5e49fc59ce02b42a2f693c738c582b36bd08e9cfe3acb8cee299216743869bd4")
            .unwrap()
    );
}

#[test]
fn e2e() -> eyre::Result<()> {
    BundleProverTester::setup(true)?;

    let mut chunk_prover = ChunkProverTester::load_prover(false)?;
    let mut batch_prover = BatchProverTester::load_prover(false)?;
    let mut bundle_prover = BundleProverTester::load_prover(true)?;

    let mut task = preset_bundle();
    let wit = task.get_or_build_witness()?;
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

    let proof =
        task.get_or_build_proof(&mut bundle_prover, &mut batch_prover, &mut chunk_prover)?;

    let evm_proof: OpenVmEvmProof = proof.into_evm_proof().unwrap().into();

    let observed_instances = &evm_proof.user_public_values;

    for (i, (&expected, &observed)) in expected_pi_hash
        .iter()
        .zip(observed_instances.iter())
        .enumerate()
    {
        assert_eq!(
            expected, observed,
            "pi inconsistent at index {i}: expected={expected}, observed={observed:?}"
        );
    }

    Ok(())
}

#[test]
fn test_execute_validium() -> eyre::Result<()> {
    BundleProverTester::setup(true)?;

    let version = testing_version_validium();

    let mut chunk_prover = ChunkProverTester::load_prover(false)?;
    let mut batch_prover = BatchProverTester::load_prover(false)?;
    let mut bundle_prover = BundleProverTester::load_prover(true)?;

    let mut task = preset_bundle_validium();
    let wit = task.get_or_build_witness()?;
    let metadata = metadata_from_bundle_witnesses(&wit)?;
    let expected_pi_hash = metadata.pi_hash_by_version(version);

    let proof =
        task.get_or_build_proof(&mut bundle_prover, &mut batch_prover, &mut chunk_prover)?;
    let evm_proof: OpenVmEvmProof = proof.into_evm_proof().unwrap().into();
    let observed_instances = &evm_proof.user_public_values;
    for (i, (&expected, &observed)) in expected_pi_hash
        .iter()
        .zip(observed_instances.iter())
        .enumerate()
    {
        assert_eq!(
            expected, observed,
            "pi inconsistent at index {i}: expected={expected}, observed={observed:?}"
        );
    }

    Ok(())
}
