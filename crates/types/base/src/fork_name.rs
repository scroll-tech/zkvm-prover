use std::fmt;

// TODO: should we use ScrollHardfork in reth?
#[derive(
    Default,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord))]
pub enum ForkName {
    #[default]
    EuclidV1,
    EuclidV2,
    Feynman,
    Galileo,
}

impl fmt::Display for ForkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ForkName::EuclidV1 => "euclidv1",
            ForkName::EuclidV2 => "euclidv2",
            ForkName::Feynman => "feynman",
            ForkName::Galileo => "galileo",
        };
        write!(f, "{}", s)
    }
}

impl ForkName {
    /// Convert ForkName to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ForkName::EuclidV1 => "euclidv1",
            ForkName::EuclidV2 => "euclidv2",
            ForkName::Feynman => "feynman",
            ForkName::Galileo => "galileo",
        }
    }
    /// Convert ForkName to its protocol version
    pub fn to_protocol_version(&self) -> u8 {
        match self {
            ForkName::EuclidV1 => 6,
            ForkName::EuclidV2 => 7,
            ForkName::Feynman => 8,
            ForkName::Galileo => 9,
        }
    }
}

impl From<Option<&str>> for ForkName {
    fn from(value: Option<&str>) -> Self {
        match value {
            None => Default::default(),
            Some("euclidv1") => ForkName::EuclidV1,
            Some("euclidv2") => ForkName::EuclidV2,
            Some("feynman") => ForkName::Feynman,
            Some("galileo") => ForkName::Galileo,
            Some(s) => unreachable!("hardfork not accepted: {s}"),
        }
    }
}

impl From<&str> for ForkName {
    fn from(value: &str) -> Self {
        match value {
            "euclidv1" => ForkName::EuclidV1,
            "euclidv2" => ForkName::EuclidV2,
            "feynman" => ForkName::Feynman,
            "galileo" => ForkName::Galileo,
            s => unreachable!("hardfork not accepted: {s}"),
        }
    }
}
