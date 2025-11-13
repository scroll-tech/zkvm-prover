use super::v7::{GenericEnvelopeV7, GenericPayloadV7};

/// Envelope@v8 represents the generic envelope type for da-codec@v8 is marked by the
/// appropriate da-codec version byte.
pub type EnvelopeV8 = GenericEnvelopeV7;

pub type PayloadV8 = GenericPayloadV7;
