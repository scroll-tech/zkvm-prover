use crate::PayloadV8;

use super::v7::GenericBatchInfoBuilderV7;

/// Builder that consumes DA-codec@v8 [`BatchHeader`][BatchHeaderV8] and builds the public-input
/// values [`BatchInfo`] for the batch-circuit.
pub type BatchInfoBuilderV8 = GenericBatchInfoBuilderV7<PayloadV8>;
