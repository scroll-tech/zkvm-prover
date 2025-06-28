use super::{
    DA_CODEC_VERSION_V8,
    v7::{GenericEnvelopeV7, GenericPayloadV7},
};

/// Envelope@v8 represents the generic envelope type for da-codec@v8 is marked by the
/// appropriate da-codec version byte.
pub type EnvelopeV8 = GenericEnvelopeV7<DA_CODEC_VERSION_V8>;

pub type PayloadV8 = GenericPayloadV7;
