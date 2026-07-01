#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{PublicInputs, Version, scroll::batch::BatchInfo};
use scroll_zkvm_types_batch::{
    BatchHeader, BatchHeaderV6, BatchHeaderV7, BatchWitness, Envelope, EnvelopeV6, EnvelopeV7,
    N_BLOB_BYTES, Payload, PayloadV6, PayloadV7, ReferenceHeader,
};

pub fn main() {
    // Number of chunk proofs to aggregate. The host must stream, in order:
    //   1. the chunk verifying-key digest ([u32; 8])
    //   2. the chunk public-values digest ([u8; 32])
    // and then attach the actual compressed chunk proof via SP1Stdin::write_proof.
    let num_chunks: u32 = sp1_zkvm::io::read::<u32>();

    for _ in 0..num_chunks {
        let vk_digest: [u32; 8] = sp1_zkvm::io::read::<[u32; 8]>();
        let pv_digest: [u8; 32] = sp1_zkvm::io::read::<[u8; 32]>();
        sp1_zkvm::lib::verify::verify_sp1_proof(&vk_digest, &pv_digest);
    }

    let witness_bytes = sp1_zkvm::io::read_vec();
    let (witness, _): (BatchWitness, _) = bincode::serde::decode_from_slice(
        &witness_bytes,
        bincode::config::standard(),
    )
    .expect("BatchCircuit: deserialisation failed");

    assert_eq!(
        num_chunks,
        witness.chunk_infos.len() as u32,
        "BatchCircuit: num_chunks does not match witness"
    );

    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);

    let batch_info = match &witness.reference_header {
        ReferenceHeader::V7_V8_V9(header) => build_batch_info_v7(&witness, header),
        ReferenceHeader::V6(header) => build_batch_info_v6(&witness, header),
        _ => panic!("BatchCircuit: unsupported reference header"),
    };

    let pi_hash: B256 = (batch_info, version).pi_hash();
    sp1_zkvm::io::commit_slice(pi_hash.as_slice());
}

fn build_batch_info_v7(witness: &BatchWitness, header: &BatchHeaderV7) -> BatchInfo {
    let mut blob_bytes = witness.blob_bytes.clone();
    blob_bytes.resize(N_BLOB_BYTES, 0);

    let envelope = EnvelopeV7::from_slice(&blob_bytes);

    let stf_version = witness.version;
    assert_eq!(
        envelope.version(),
        Some(stf_version),
        "BatchCircuit: blob codec version mismatch"
    );
    assert_eq!(
        header.version(),
        stf_version,
        "BatchCircuit: batch header version mismatch"
    );

    let payload = PayloadV7::from_envelope(&envelope);

    let point_eval_witness = witness
        .point_eval_witness
        .as_ref()
        .expect("point_eval_witness missing for header::v7");
    let challenge_digest = envelope.challenge_digest(header.blob_versioned_hash);
    scroll_zkvm_types_batch::blob_consistency::verify_blob_versioned_hash(
        &witness.blob_bytes,
        header.blob_versioned_hash,
        challenge_digest,
        point_eval_witness,
    );

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
