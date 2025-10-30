//! Module includes various types and logic pertaining to the versioning system under Scroll's
//! proving system.
//!
//! In order to identify the appropriate EVM fork logic and codec version for the encoded data, we
//! make use of a versioning system specified by the tuple `(domain,stf_version)`.
//!
//! The [`Domain`] indicates the execution of "what" are we proving?
//!
//! The [`STFVersion`] indicates an incremental version used within that domain.
//!
//! The tuple `(domain,stf_version)` maps to a unique tuple `(fork,codec)` that tells us which EVM fork
//! logic and codec logic must be utilised to decode data and execute transactions that are being
//! proven.
//!
//! The version is a single byte that encodes the tuple `(domain,stf_version)` such that:
//!
//! | bit index | purpose     |
//! |-----------|-------------|
//! | 0..=1     | domain      |
//! | 2..=7     | stf_version |

use crate::public_inputs::ForkName;

/// Protocol `domain` in the protocol=(domain,version) tuple.
///
/// Domain is represented using 2 bits, i.e. we can support at the most 4 domains as per the latest
/// codec.
#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum Domain {
    /// Domain used for Scroll.
    Scroll = 0,
    /// Domain used for L3 validiums running on L2 Scroll.
    Validium = 1,
}

impl From<u8> for Domain {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Scroll,
            1 => Self::Validium,
            value => unreachable!("unsupported domain={value}"),
        }
    }
}

/// The state-transition-function's incremental version.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
pub enum STFVersion {
    /// Validium@v1.
    V1 = 1,
    /// Scroll@v6.
    V6 = 6,
    /// Scroll@v7.
    V7 = 7,
    /// Scroll@v8.
    V8 = 8,
}

impl From<u8> for STFVersion {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::V1,
            6 => Self::V6,
            7 => Self::V7,
            8 => Self::V8,
            value => unreachable!("unsupported stf-version={value}"),
        }
    }
}

/// The codec version.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
pub enum Codec {
    /// da-codec@v6.
    V6,
    /// da-codec@v7.
    V7,
    /// da-codec@v8.
    V8,
    /// da-codec@v9.
    V9,
}

/// The number of bits used for [`STFVersion`].
const N_BITS_STF_VERSION: u8 = 6;

/// Mask and get the [`STFVersion`] from the version byte.
const MASK_STF_VERSION: u8 = 0b00111111;

/// A fully parsed version that includes all necessary identifiers.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
pub struct Version {
    /// Domain.
    pub domain: Domain,
    /// STF-version.
    pub stf_version: STFVersion,
    /// EVM fork name.
    pub fork: ForkName,
    /// DA-codec version.
    pub codec: Codec,
}

impl Version {
    pub const fn as_version_byte(&self) -> u8 {
        ((self.domain as u8) << N_BITS_STF_VERSION) + (self.stf_version as u8)
    }

    pub const fn euclid_v1() -> Self {
        Self {
            domain: Domain::Scroll,
            stf_version: STFVersion::V6,
            fork: ForkName::EuclidV1,
            codec: Codec::V6,
        }
    }

    pub const fn euclid_v2() -> Self {
        Self {
            domain: Domain::Scroll,
            stf_version: STFVersion::V7,
            fork: ForkName::EuclidV2,
            codec: Codec::V7,
        }
    }

    pub const fn feynman() -> Self {
        Self {
            domain: Domain::Scroll,
            stf_version: STFVersion::V8,
            fork: ForkName::Feynman,
            codec: Codec::V8,
        }
    }

    pub const fn validium_v1() -> Self {
        Self {
            domain: Domain::Validium,
            stf_version: STFVersion::V1,
            fork: ForkName::Feynman,
            codec: Codec::V9,
        }
    }

    pub fn is_validium(&self) -> bool {
        self.domain == Domain::Validium
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::feynman()
    }
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        let domain = Domain::from(value >> N_BITS_STF_VERSION);
        let stf_version = STFVersion::from(value & MASK_STF_VERSION);

        match (domain, stf_version) {
            (Domain::Scroll, STFVersion::V6) => Self::euclid_v1(),
            (Domain::Scroll, STFVersion::V7) => Self::euclid_v2(),
            (Domain::Scroll, STFVersion::V8) => Self::feynman(),
            (Domain::Validium, STFVersion::V1) => Self::validium_v1(),
            (domain, stf_version) => {
                unreachable!("unsupported version=({domain:?}, {stf_version:?})")
            }
        }
    }
}

/// Version byte for Validium @ v1.
pub const VALIDIUM_V1: u8 =
    ((Domain::Validium as u8) << N_BITS_STF_VERSION) + (STFVersion::V1 as u8);
