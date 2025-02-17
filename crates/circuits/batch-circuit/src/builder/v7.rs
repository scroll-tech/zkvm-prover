use core::unimplemented;

use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeaderV7, PayloadV7, BatchInfo},
    chunk::ChunkInfo,
};
use vm_zstd::process;

/// Builder that consumes DA-codec@v7 [`BatchHeader`][BatchHeaderV7] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV7;

impl BatchInfoBuilderV7 {
    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    pub fn build(
        header: &BatchHeaderV7,
        chunks_info: &[ChunkInfo],
        blob_bytes: &[u8],
    ) -> BatchInfo {
        let version = blob_bytes[0];
        assert!(version >= 7u8);

        unimplemented!();
    }
}
