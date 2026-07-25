//! [`Principal`] — an issuer-namespaced subject.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The separator between issuer and subject in a principal's string form.
const SEP: char = ':';

/// Who vouches for a [`Principal`]'s subject.
///
/// The set is deliberately **open for extension but closed for guessing**:
///
/// - `#[non_exhaustive]` lets a later build add an authenticator (NIP-05,
///   WebAuthn, mTLS, …) without it being a breaking change for downstream
///   `match` arms; but
/// - [`Issuer::parse`] has an explicit arm per known issuer and *rejects*
///   anything else. An unknown prefix is a [`PrincipalParseError::UnknownIssuer`],
///   never a silently-accepted opaque string. Adding an issuer therefore
///   requires adding its validation rule in the same commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Issuer {
    /// plexus-idp: a server-minted UUID v4 (`plexus-idp/src/core.rs:95`).
    Idp,
    /// A self-sovereign nostr identity: a 32-byte secp256k1 x-only pubkey.
    Nostr,
    /// A machine credential minted as an API key.
    ApiKey,
}

impl Issuer {
    /// The issuer's wire prefix.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idp => "idp",
            Self::Nostr => "nostr",
            Self::ApiKey => "apikey",
        }
    }

    /// Parse an issuer prefix. Unknown prefixes are an error, not a new issuer.
    pub fn parse(s: &str) -> Result<Self, PrincipalParseError> {
        match s {
            "idp" => Ok(Self::Idp),
            "nostr" => Ok(Self::Nostr),
            "apikey" => Ok(Self::ApiKey),
            other => Err(PrincipalParseError::UnknownIssuer(other.to_string())),
        }
    }

    /// Validate a subject against this issuer's rules.
    fn validate(self, subject: &str) -> Result<(), PrincipalParseError> {
        if subject.is_empty() {
            return Err(PrincipalParseError::EmptySubject(self));
        }
        if subject.contains(SEP) {
            return Err(PrincipalParseError::SubjectContainsSeparator(self));
        }

        match self {
            // A canonical lowercase hyphenated UUID, exactly as idp mints it
            // (`Uuid::new_v4().to_string()`). Braced/URN/simple forms are
            // rejected so that one identity has exactly one rendering and
            // `Display`/`FromStr` round-trip byte-for-byte.
            Self::Idp => {
                let parsed = uuid::Uuid::parse_str(subject)
                    .map_err(|_| PrincipalParseError::InvalidUuid(subject.to_string()))?;
                if parsed.hyphenated().to_string() != subject {
                    return Err(PrincipalParseError::InvalidUuid(subject.to_string()));
                }
                Ok(())
            }

            // 64 lowercase hex characters — the x-only pubkey encoding every
            // nostr implementation uses. Uppercase is rejected rather than
            // normalized: normalizing would break the exact round-trip and
            // give one key two principals.
            Self::Nostr => {
                if subject.len() != 64 {
                    return Err(PrincipalParseError::InvalidNostrPubkey {
                        subject: subject.to_string(),
                        reason: "expected exactly 64 hex characters",
                    });
                }
                if !subject
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(PrincipalParseError::InvalidNostrPubkey {
                        subject: subject.to_string(),
                        reason: "expected lowercase hex only",
                    });
                }
                Ok(())
            }

            // An opaque key id. Constrained to printable, non-whitespace ASCII
            // so a principal is always safely renderable in a log line, a URL
            // segment, or a header value.
            Self::ApiKey => {
                if subject
                    .bytes()
                    .any(|b| !b.is_ascii_graphic() || b == b'"' || b == b'\\')
                {
                    return Err(PrincipalParseError::InvalidApiKeyId(subject.to_string()));
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a string is not a valid [`Principal`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalParseError {
    /// No `:` separator at all.
    #[error("principal `{0}` has no `{SEP}` separator; expected `<issuer>{SEP}<subject>`")]
    MissingSeparator(String),

    /// The prefix is not a known issuer.
    #[error("unknown principal issuer `{0}`; known issuers: idp, nostr, apikey")]
    UnknownIssuer(String),

    /// The subject was empty.
    #[error("principal issuer `{0}` has an empty subject")]
    EmptySubject(Issuer),

    /// The subject contained a second `:`, making the rendering ambiguous.
    #[error("principal subject for issuer `{0}` contains a `{SEP}`, which is ambiguous")]
    SubjectContainsSeparator(Issuer),

    /// `idp:` subject was not a canonical hyphenated UUID.
    #[error("principal subject `{0}` is not a canonical hyphenated UUID")]
    InvalidUuid(String),

    /// `nostr:` subject was not a 64-character lowercase hex pubkey.
    #[error("principal subject `{subject}` is not a valid nostr pubkey: {reason}")]
    InvalidNostrPubkey {
        /// The rejected subject.
        subject: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// `apikey:` subject contained non-printable or quoting characters.
    #[error("principal subject `{0}` is not a valid api key id")]
    InvalidApiKeyId(String),
}

/// An issuer-namespaced subject: `idp:<uuid>`, `nostr:<64-hex>`, `apikey:<id>`.
///
/// # Invariants
///
/// The fields are private and both constructors ([`Principal::new`] and
/// [`FromStr`]) validate, so *every* `Principal` value in existence satisfies
/// its issuer's rules. `Deserialize` goes through `FromStr`, so a JSON document
/// cannot smuggle in an invalid one either.
///
/// [`Display`](fmt::Display) and [`FromStr`] round-trip **exactly** — no
/// normalization is performed anywhere, because normalizing would let one
/// subject have two renderings and therefore two unequal `Principal`s.
///
/// # Wire form
///
/// A plain JSON string (`"idp:6ba7b810-9dad-11d1-80b4-00c04fd430c8"`), not an
/// object — the `#[serde(transparent)]`-like behavior PLX-75 asks for, but
/// implemented by hand so that deserialization can enforce validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal {
    issuer: Issuer,
    subject: String,
}

impl Principal {
    /// Build a principal, validating the subject against the issuer's rules.
    ///
    /// # Errors
    ///
    /// See [`PrincipalParseError`].
    pub fn new(issuer: Issuer, subject: impl Into<String>) -> Result<Self, PrincipalParseError> {
        let subject = subject.into();
        issuer.validate(&subject)?;
        Ok(Self { issuer, subject })
    }

    /// An idp-minted principal from a UUID.
    pub fn idp(uuid: &uuid::Uuid) -> Self {
        // A `Uuid` always renders as a canonical hyphenated string, so this
        // cannot fail — but it still goes through the validating constructor
        // so there is exactly one path that builds a `Principal`.
        Self::new(Issuer::Idp, uuid.hyphenated().to_string())
            .expect("a canonical Uuid is always a valid idp subject")
    }

    /// Who vouches for this subject.
    pub fn issuer(&self) -> Issuer {
        self.issuer
    }

    /// The issuer-scoped subject, without the prefix.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.issuer.as_str(), SEP, self.subject)
    }
}

impl FromStr for Principal {
    type Err = PrincipalParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split on the FIRST separator; `Issuer::validate` then rejects any
        // further `:` in the remainder, so `idp:a:b` is an error rather than a
        // principal with a colon-bearing subject.
        let (prefix, subject) = s
            .split_once(SEP)
            .ok_or_else(|| PrincipalParseError::MissingSeparator(s.to_string()))?;
        let issuer = Issuer::parse(prefix)?;
        issuer.validate(subject)?;
        Ok(Self {
            issuer,
            subject: subject.to_string(),
        })
    }
}

impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const PUBKEY: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn samples() -> Vec<&'static str> {
        vec![
            "idp:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "nostr:3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            "apikey:ak_live_01HQ8ZQK",
        ]
    }

    // AC4: FromStr/Display round-trip for idp/nostr/apikey samples.
    #[test]
    fn display_fromstr_round_trip_exactly() {
        for s in samples() {
            let p: Principal = s.parse().expect(s);
            assert_eq!(p.to_string(), s, "Display must reproduce the input exactly");
            let again: Principal = p.to_string().parse().unwrap();
            assert_eq!(p, again);
        }
    }

    #[test]
    fn issuer_and_subject_are_split_correctly() {
        let p: Principal = format!("idp:{UUID}").parse().unwrap();
        assert_eq!(p.issuer(), Issuer::Idp);
        assert_eq!(p.subject(), UUID);

        let p: Principal = format!("nostr:{PUBKEY}").parse().unwrap();
        assert_eq!(p.issuer(), Issuer::Nostr);
        assert_eq!(p.subject(), PUBKEY);

        let p: Principal = "apikey:ak_live_01HQ8ZQK".parse().unwrap();
        assert_eq!(p.issuer(), Issuer::ApiKey);
        assert_eq!(p.subject(), "ak_live_01HQ8ZQK");
    }

    // AC4: serde round-trip, and the wire form is a bare string.
    #[test]
    fn serde_round_trips_as_a_plain_string() {
        for s in samples() {
            let p: Principal = s.parse().unwrap();
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{s}\""), "wire form must be a bare string");
            let back: Principal = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn deserialization_enforces_validation() {
        // A hand-written document cannot smuggle in an invalid principal.
        let err = serde_json::from_str::<Principal>("\"ldap:someone\"").unwrap_err();
        assert!(err.to_string().contains("unknown principal issuer"), "{err}");

        let err = serde_json::from_str::<Principal>("\"nostr:NOTHEX\"").unwrap_err();
        assert!(err.to_string().contains("nostr pubkey"), "{err}");
    }

    // AC4: reject-cases.
    #[test]
    fn rejects_unknown_issuer() {
        assert!(matches!(
            "ldap:someone".parse::<Principal>(),
            Err(PrincipalParseError::UnknownIssuer(i)) if i == "ldap"
        ));
        // Capitalization of the issuer is not a known issuer either.
        assert!(matches!(
            "IDP:6ba7b810-9dad-11d1-80b4-00c04fd430c8".parse::<Principal>(),
            Err(PrincipalParseError::UnknownIssuer(_))
        ));
    }

    #[test]
    fn rejects_empty_subject() {
        for issuer in ["idp", "nostr", "apikey"] {
            let s = format!("{issuer}:");
            assert!(
                matches!(
                    s.parse::<Principal>(),
                    Err(PrincipalParseError::EmptySubject(_))
                ),
                "{s} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(matches!(
            "idp".parse::<Principal>(),
            Err(PrincipalParseError::MissingSeparator(_))
        ));
        assert!(matches!(
            UUID.parse::<Principal>(),
            Err(PrincipalParseError::MissingSeparator(_))
        ));
    }

    #[test]
    fn rejects_nostr_pubkey_of_wrong_length() {
        let short = &PUBKEY[..63];
        let long = format!("{PUBKEY}a");
        assert_eq!(short.len(), 63);
        assert_eq!(long.len(), 65);

        for bad in [short.to_string(), long] {
            let s = format!("nostr:{bad}");
            match s.parse::<Principal>() {
                Err(PrincipalParseError::InvalidNostrPubkey { reason, .. }) => {
                    assert_eq!(reason, "expected exactly 64 hex characters");
                }
                other => panic!("{s} should be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_uppercase_nostr_hex() {
        let upper = PUBKEY.to_uppercase();
        assert_eq!(upper.len(), 64);
        let s = format!("nostr:{upper}");
        match s.parse::<Principal>() {
            Err(PrincipalParseError::InvalidNostrPubkey { reason, .. }) => {
                assert_eq!(reason, "expected lowercase hex only");
            }
            other => panic!("uppercase hex should be rejected, got {other:?}"),
        }
    }

    #[test]
    fn rejects_embedded_second_colon() {
        for s in [
            format!("idp:{UUID}:extra"),
            format!("nostr:{PUBKEY}:extra"),
            "apikey:ak:live".to_string(),
        ] {
            assert!(
                matches!(
                    s.parse::<Principal>(),
                    Err(PrincipalParseError::SubjectContainsSeparator(_))
                ),
                "{s} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_non_canonical_uuid() {
        for bad in [
            "not-a-uuid",
            "6ba7b8109dad11d180b400c04fd430c8",              // simple form
            "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}",        // braced form
            "6BA7B810-9DAD-11D1-80B4-00C04FD430C8",          // uppercase
        ] {
            let s = format!("idp:{bad}");
            assert!(
                matches!(
                    s.parse::<Principal>(),
                    Err(PrincipalParseError::InvalidUuid(_))
                ),
                "{s} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_unprintable_api_key_ids() {
        for bad in ["ak live", "ak\tlive", "ak\"live"] {
            let s = format!("apikey:{bad}");
            assert!(
                matches!(
                    s.parse::<Principal>(),
                    Err(PrincipalParseError::InvalidApiKeyId(_))
                ),
                "{s:?} should be rejected"
            );
        }
    }

    #[test]
    fn new_validates_like_from_str() {
        assert!(Principal::new(Issuer::Idp, UUID).is_ok());
        assert!(Principal::new(Issuer::Idp, "nope").is_err());
        assert!(Principal::new(Issuer::Nostr, PUBKEY).is_ok());
        assert!(Principal::new(Issuer::Nostr, "").is_err());
    }

    #[test]
    fn idp_helper_matches_manual_construction() {
        let u = uuid::Uuid::parse_str(UUID).unwrap();
        assert_eq!(Principal::idp(&u), Principal::new(Issuer::Idp, UUID).unwrap());
        assert_eq!(Principal::idp(&u).to_string(), format!("idp:{UUID}"));
    }

    #[test]
    fn principals_from_different_issuers_never_collide() {
        let a = Principal::new(Issuer::ApiKey, UUID).unwrap();
        let b = Principal::new(Issuer::Idp, UUID).unwrap();
        assert_ne!(a, b);
        assert_ne!(a.to_string(), b.to_string());
    }
}
