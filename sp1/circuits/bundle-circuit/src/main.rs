#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{PublicInputs, Version, scroll::bundle::BundleInfo};
use scroll_zkvm_types_bundle::BundleWitness;

pub fn main() {
    // Number of batch proofs to aggregate. The host must stream, in order:
    //   1. the batch verifying-key digest ([u32; 8])
    //   2. the batch public-values digest ([u8; 32])
    // and then attach the actual compressed batch proof via SP1Stdin::write_proof.
    let num_batches: u32 = sp1_zkvm::io::read::<u32>();

    for _ in 0..num_batches {
        let vk_digest: [u32; 8] = sp1_zkvm::io::read::<[u32; 8]>();
        let pv_digest: [u8; 32] = sp1_zkvm::io::read::<[u8; 32]>();
        sp1_zkvm::lib::verify::verify_sp1_proof(&vk_digest, &pv_digest);
    }

    let witness_bytes = sp1_zkvm::io::read_vec();
    let (witness, _): (BundleWitness, _) = bincode::serde::decode_from_slice(
        &witness_bytes,
        bincode::config::standard(),
    )
    .expect("BundleCircuit: deserialisation failed");

    assert_eq!(
        num_batches,
        witness.batch_infos.len() as u32,
        "BundleCircuit: num_batches does not match witness"
    );

    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);

    let bundle_info = BundleInfo::from(&witness);

    let pi_hash: B256 = (bundle_info, version).pi_hash();
    sp1_zkvm::io::commit_slice(pi_hash.as_slice());
}
