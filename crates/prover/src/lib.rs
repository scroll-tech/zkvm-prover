#[rustfmt::skip]
mod commitments;

mod error;
pub use error::Error;

mod proof;
pub use proof::{BatchProof, BundleProof, ChunkProof, WrappedProof};

mod prover;
pub use prover::{
    BatchProver, BatchProverType, BundleProver, BundleProverType, ChunkProver, ChunkProverType,
    Prover, ProverType, SC,
};

pub mod setup;

pub mod task;

pub mod utils;

#[cfg(test)]
mod tests {
    use sbv::primitives::B256;

    trait FromBytes: Sized {
        fn from_bytes(bytes: &[u8]) -> Self;
    }

    impl FromBytes for scroll_zkvm_circuit_input_types::bundle::BundleInfo {
        fn from_bytes(bytes: &[u8]) -> Self {
            assert_eq!(172, bytes.len(), "not correct len");
            Self {
                chain_id: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
                num_batches: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
                prev_state_root: B256::from_slice(&bytes[12..44]),
                prev_batch_hash: B256::from_slice(&bytes[44..76]),
                post_state_root: B256::from_slice(&bytes[76..108]),
                batch_hash: B256::from_slice(&bytes[108..140]),
                withdraw_root: B256::from_slice(&bytes[140..172]),
            }
        }
    }

    #[test]
    fn test_compare_onchain_offchain() -> eyre::Result<()> {
        let onchain_pi_hex = std::fs::read_to_string(
            std::path::Path::new("./testdata")
                .join("failed")
                .join("trace_pi.hex"),
        )?;
        let onchain_pi_hex = onchain_pi_hex.trim_end();
        let onchain_pi = hex::decode(onchain_pi_hex)?;
        let onchain_pi =
            scroll_zkvm_circuit_input_types::bundle::BundleInfo::from_bytes(&onchain_pi);

        let offchain_proof = crate::proof::BundleProof::from_json(
            std::path::Path::new("./testdata")
                .join("failed")
                .join("bundle-proof-failed.json"),
        )?;
        let offchain_pi = &offchain_proof.metadata.bundle_info;

        println!("onchain pi  = {:#?}", onchain_pi);
        println!("offchain pi = {:#?}", offchain_pi);

        assert_eq!(onchain_pi.chain_id, offchain_pi.chain_id);
        assert_eq!(onchain_pi.num_batches, offchain_pi.num_batches);
        assert_eq!(onchain_pi.prev_state_root, offchain_pi.prev_state_root);
        assert_eq!(onchain_pi.prev_batch_hash, offchain_pi.prev_batch_hash);
        assert_eq!(onchain_pi.post_state_root, offchain_pi.post_state_root);
        assert_eq!(onchain_pi.batch_hash, offchain_pi.batch_hash);
        assert_eq!(onchain_pi.withdraw_root, offchain_pi.withdraw_root);

        let onchain_proof_hex = std::fs::read_to_string(
            std::path::Path::new("./testdata")
                .join("failed")
                .join("trace_proof.hex"),
        )?;
        let onchain_proof_hex = onchain_proof_hex.trim_end();
        let onchain_proof = hex::decode(onchain_proof_hex)?;

        let offchain_proof = offchain_proof.as_proof();
        let offchain_proof = crate::proof::EvmProof::from(&offchain_proof);

        assert_eq!(
            &onchain_proof[0x00..0x180],
            &offchain_proof.instances[0x00..0x180],
            "accumulator mismatch"
        );
        assert_eq!(
            &onchain_proof[0x180..],
            &offchain_proof.proof,
            "proof mismatch"
        );

        Ok(())
    }
}
