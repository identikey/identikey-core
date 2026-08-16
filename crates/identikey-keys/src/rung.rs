//! Custody rungs and access levels. Stored as the lowercase tags (`c2`, `a3`).

use std::fmt;
use std::str::FromStr;

/// Who can produce a signature with the user's key. See `docs/custody-ladder.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum CustodyRung {
    C0,
    C1,
    C2,
    C3,
    C4,
}

impl CustodyRung {
    /// Rungs at which IdentiKey holds the managed Sign key.
    #[must_use]
    pub const fn holds_managed_key(self) -> bool {
        matches!(self, Self::C1 | Self::C2)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C0 => "c0",
            Self::C1 => "c1",
            Self::C2 => "c2",
            Self::C3 => "c3",
            Self::C4 => "c4",
        }
    }
}

impl fmt::Display for CustodyRung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CustodyRung {
    type Err = ParseRungError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "c0" => Ok(Self::C0),
            "c1" => Ok(Self::C1),
            "c2" => Ok(Self::C2),
            "c3" => Ok(Self::C3),
            "c4" => Ok(Self::C4),
            other => Err(ParseRungError::UnknownRung(other.to_owned())),
        }
    }
}

/// How the user authenticates *to the party holding the key*.
///
/// Local user verification is not an access level and has no variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum AccessLevel {
    A0,
    A1,
    A2,
    A3,
    A4,
}

impl AccessLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A0 => "a0",
            Self::A1 => "a1",
            Self::A2 => "a2",
            Self::A3 => "a3",
            Self::A4 => "a4",
        }
    }
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AccessLevel {
    type Err = ParseRungError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "a0" => Ok(Self::A0),
            "a1" => Ok(Self::A1),
            "a2" => Ok(Self::A2),
            "a3" => Ok(Self::A3),
            "a4" => Ok(Self::A4),
            other => Err(ParseRungError::UnknownAccess(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseRungError {
    #[error("unknown custody rung {0:?}")]
    UnknownRung(String),
    #[error("unknown access level {0:?}")]
    UnknownAccess(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_key_rungs() {
        assert!(CustodyRung::C1.holds_managed_key());
        assert!(CustodyRung::C2.holds_managed_key());
        assert!(!CustodyRung::C0.holds_managed_key());
        assert!(!CustodyRung::C3.holds_managed_key());
        assert!(!CustodyRung::C4.holds_managed_key());
    }

    #[test]
    fn round_trip() {
        for tag in ["c0", "c1", "c2", "c3", "c4"] {
            assert_eq!(tag.parse::<CustodyRung>().map(|r| r.as_str()), Ok(tag));
        }
        for tag in ["a0", "a1", "a2", "a3", "a4"] {
            assert_eq!(tag.parse::<AccessLevel>().map(|a| a.as_str()), Ok(tag));
        }
    }
}
