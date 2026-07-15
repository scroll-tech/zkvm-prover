extern crate ceno_rt;

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{
    MultiVersionPublicInputs, PublicInputs, Version, scroll::batch::BatchInfo,
};
use scroll_zkvm_types_batch::{
    BatchHeader, BatchHeaderV6, BatchHeaderV7, BatchWitness, Envelope, EnvelopeV6, EnvelopeV7,
    N_BLOB_BYTES, Payload, PayloadV6, PayloadV7, ReferenceHeader,
};

fn main() {
    let child_pi_hashes: Vec<[u8; 32]> = ceno_rt::read();
    let witness: BatchWitness = ceno_rt::read();

    assert_eq!(
        child_pi_hashes.len(),
        witness.chunk_infos.len(),
        "BatchCircuit: child metadata count does not match witness"
    );

    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);
    for (child_hash, info) in child_pi_hashes.iter().zip(&witness.chunk_infos) {
        assert_eq!(
            child_hash.as_slice(),
            info.pi_hash_by_version(version).as_slice(),
            "BatchCircuit: child pi_hash metadata mismatch"
        );
    }

    let batch_info = match &witness.reference_header {
        ReferenceHeader::V7_V8_V9(header) => build_batch_info_v7(&witness, header),
        ReferenceHeader::V6(header) => build_batch_info_v6(&witness, header),
        _ => panic!("BatchCircuit: unsupported reference header"),
    };

    let pi_hash: B256 = (batch_info, version).pi_hash();
    ceno_rt::commit(pi_hash.as_slice());
}

fn build_batch_info_v7(witness: &BatchWitness, header: &BatchHeaderV7) -> BatchInfo {
    let mut blob_bytes = witness.blob_bytes.clone();
    blob_bytes.resize(N_BLOB_BYTES, 0);

    let envelope = EnvelopeV7::from_slice(&blob_bytes);
    let stf_version = witness.version;
    assert_eq!(envelope.version(), Some(stf_version));
    assert_eq!(header.version(), stf_version);

    let payload = PayloadV7::from_envelope(&envelope);
    let (first, last) = payload.validate(header, &witness.chunk_infos);
    BatchInfo {
        parent_state_root: first.prev_state_root,
        parent_batch_hash: header.parent_batch_hash,
        state_root: last.post_state_root,
        batch_hash: header.batch_hash(),
        chain_id: last.chain_id,
        withdraw_root: last.withdraw_root,
        prev_msg_queue_hash: first.prev_msg_queue_hash,
        post_msg_queue_hash: last.post_msg_queue_hash,
        encryption_key: None,
    }
}

fn build_batch_info_v6(witness: &BatchWitness, header: &BatchHeaderV6) -> BatchInfo {
    let envelope = EnvelopeV6::from_slice(&witness.blob_bytes);
    let payload = PayloadV6::from_envelope(&envelope);
    let (first, last) = payload.validate(header, &witness.chunk_infos);

    BatchInfo {
        parent_state_root: first.prev_state_root,
        parent_batch_hash: header.parent_batch_hash,
        state_root: last.post_state_root,
        batch_hash: header.batch_hash(),
        chain_id: last.chain_id,
        withdraw_root: last.withdraw_root,
        prev_msg_queue_hash: Default::default(),
        post_msg_queue_hash: Default::default(),
        encryption_key: Default::default(),
    }
}
