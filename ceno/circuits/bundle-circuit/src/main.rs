extern crate ceno_rt;

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{
    MultiVersionPublicInputs, PublicInputs, Version, scroll::bundle::BundleInfo,
};
use scroll_zkvm_types_bundle::BundleWitness;

fn main() {
    let child_pi_hashes: Vec<[u8; 32]> = ceno_rt::read();
    let witness: BundleWitness = ceno_rt::read();

    assert_eq!(
        child_pi_hashes.len(),
        witness.batch_infos.len(),
        "BundleCircuit: child metadata count does not match witness"
    );

    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);
    for (child_hash, info) in child_pi_hashes.iter().zip(&witness.batch_infos) {
        assert_eq!(
            child_hash.as_slice(),
            info.pi_hash_by_version(version).as_slice(),
            "BundleCircuit: child pi_hash metadata mismatch"
        );
    }

    let bundle_info = BundleInfo::from(&witness);
    let pi_hash: B256 = (bundle_info, version).pi_hash();
    ceno_rt::commit(pi_hash.as_slice());
}
