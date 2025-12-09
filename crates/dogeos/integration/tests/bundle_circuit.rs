use sbv_primitives::alloy_primitives;
use dogeos_zkvm_integration::testers::batch::{mock_batch_witness, BatchProverTester};
use dogeos_zkvm_integration::testers::bundle::{mock_bundle_witness, BundleProverTester};
use dogeos_zkvm_integration::testers::chunk::{mock_chunk_witness, ChunkProverTester};
use scroll_zkvm_integration::{prove_verify, prove_verify_single_evm, testing_version, ProverTester, TaskProver};
use scroll_zkvm_integration::utils::metadata_from_bundle_witnesses;
use scroll_zkvm_types::proof::OpenVmEvmProof;
use scroll_zkvm_types::public_inputs::dogeos::bundle::DogeOsBundleInfo;
use scroll_zkvm_types::public_inputs::{ForkName, MultiVersionPublicInputs};
use scroll_zkvm_types::version::Version;

#[test]
fn e2e() -> eyre::Result<()> {
    BundleProverTester::setup(true)?;

    let mut chunk_prover = ChunkProverTester::load_prover(false)?;
    let mut batch_prover = BatchProverTester::load_prover(false)?;
    let mut bundle_prover = BundleProverTester::load_prover(true)?;
    e2e_inner(&mut chunk_prover, &mut batch_prover, &mut bundle_prover)?;

    Ok(())
}

fn e2e_inner(
    chunk_prover: &mut impl TaskProver,
    batch_prover: &mut impl TaskProver,
    bundle_prover: &mut impl TaskProver,
) -> eyre::Result<()> {
    let chunk_witness = mock_chunk_witness()?;
    let batch_witness = mock_batch_witness(&chunk_witness)?;
    let bundle_witness = mock_bundle_witness(&batch_witness)?;
    let bundle_info = DogeOsBundleInfo::from(&bundle_witness);
    let expected_pi_hash = bundle_info.pi_hash_by_version(Version::feynman());

    let chunk_proof = prove_verify::<ChunkProverTester>(chunk_prover, &chunk_witness, &[])?;
    let batch_proof = prove_verify::<BatchProverTester>(batch_prover, &batch_witness, &[chunk_proof])?;
    let bundle_proof = prove_verify_single_evm::<BundleProverTester>(bundle_prover, &bundle_witness, &[batch_proof])?;


    let evm_proof: OpenVmEvmProof = bundle_proof.into_evm_proof().unwrap().into();

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
