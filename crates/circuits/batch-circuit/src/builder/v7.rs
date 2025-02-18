use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeaderV7, BatchInfo, Bytes48},
    chunk::ChunkInfo,
};

/// Builder that consumes DA-codec@v7 [`BatchHeader`][BatchHeaderV7] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub struct BatchInfoBuilderV7;

impl BatchInfoBuilderV7 {
    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    pub fn build(
        _header: &BatchHeaderV7,
        _chunks_info: &[ChunkInfo],
        _blob_bytes: &[u8],
        _kzg_commitment: &Bytes48,
        _kzg_proof: &Bytes48,
    ) -> BatchInfo {
        unimplemented!()
    }
}
