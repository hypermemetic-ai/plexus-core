//! DYNAUTH-12 (D3, TM-4) · peer tokens: what a service signs for the peer a
//! call is forwarded to, so the peer can check what it is told rather than
//! believe who told it.
//!
//! A token is a compact JWS (RFC 7515) of a JWT (RFC 7519), signed EdDSA
//! (Ed25519, RFC 8037), header `{"alg":"EdDSA","typ":"plexus-peer+jwt","kid"}`:
//!
//! | claim | what |
//! | -- | -- |
//! | `iss` | the issuing service's key, `key:<hex>` |
//! | `sub` | the original caller (the first hop's admitted principal) |
//! | `act` | the actor chain, nearest first, nested as RFC 8693 §4.1 nests it |
//! | `aud` | exactly one peer: its key (`key:<hex>`), or `pipe:<name>` for a child on the issuer's own pipe |
//! | `scope` | space-separated `grant@scope` entries: the caller's reach ∩ the peer's needs ∩ consent |
//! | `cnf.jkt` | the RFC 7638 thumbprint of the peer's Ed25519 key (RFC 7800, RFC 9449 §6); absent for a pipe |
//! | `call`, `method` | the forwarded call's id and the method it names |
//! | `jti`, `iat`, `exp` | unique; `exp − iat ≤ 60 s` |
//!
//! **Verifying** ([`Verifier`]): `alg` is pinned to EdDSA (never read from the
//! token to choose an algorithm, RFC 8725 §3.1), `typ` must be
//! `plexus-peer+jwt` (§3.11), `kid` must name a key the verifier trusts (a
//! JWKS it was given or fetched, `dyn.jwks`), the signature is checked with
//! `verify_strict`, `aud` must be the verifier's own, `iat`/`exp` within
//! ±30 s of now and `exp − iat ≤ 60 s`, and a `jti` seen before is refused
//! until its `exp` (a replay cache bounded by 60 s × the call rate).
//!
//! **Proof of possession** ([`prove`], [`check_proof`]): whoever *presents* a
//! token bound to a key (`cnf.jkt`) — a remote peer calling its service back
//! under the call the token was minted for — signs a proof with that key:
//! a compact JWS, header `{"alg":"EdDSA","typ":"plexus-pop+jwt","jwk"}`,
//! claims `{ath, jti, method, call, iat}` (`ath`: base64url sha256 of the
//! token, as DPoP's, RFC 9449 §4.2). The proof's key must be the token's
//! `cnf.jkt`, its `method` and `call` the ones it is presented for, its
//! `iat` within ±30 s, its `jti` new. A peer on its issuer's own pipe needs
//! no proof (D3: the pipe is the issuer's alone).
//!
//! **Exchange** ([`TokenIssuer::exchange`], RFC 8693 semantics): a token
//! presented for an onward call becomes one for the next peer — the same
//! `sub`, `act` extended by the presenter, `aud` the next peer, and a scope
//! that is the presented one's or narrower, never wider ([`narrow`]).
//!
//! **Audit** (DYNAUTH-7, TM-7): every mint and exchange writes one
//! [`AuditRecord`] — iss, sub, the actor chain, aud, scope, call, jti, exp,
//! method — as a `tracing` event on target `plexus::audit` and to the
//! issuer's [`TokenAudit`] sink. Never the token, never a proof.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The `typ` of a peer token (RFC 8725 §3.11: explicit typing).
pub const TOKEN_TYP: &str = "plexus-peer+jwt";
/// The `typ` of a proof of possession.
pub const PROOF_TYP: &str = "plexus-pop+jwt";
/// The one algorithm: EdDSA over Ed25519 (RFC 8037).
pub const ALG: &str = "EdDSA";
/// A token lives at most this long (`exp − iat`), D3.
pub const MAX_LIFETIME: Duration = Duration::from_secs(60);
/// How far apart two clocks may be.
pub const SKEW: Duration = Duration::from_secs(30);
/// The method a proof of possession names to exchange a token
/// ([`TokenIssuer::exchange`]), under the token's own `call`.
pub const EXCHANGE: &str = "exchange";
/// RFC 8693's identifier of the token type issued.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
/// The context a peer's key proof at `_info` is signed over (domain
/// separation: no other signature can be passed off as one).
pub const KEY_PROOF_CONTEXT: &str = "plexus-peer-key/v1";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>, TokenError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|_| TokenError::Malformed("not base64url".into()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seconds since the epoch, now.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

/// A fresh random id (128 bits, base64url).
fn random_id() -> String {
    b64(uuid::Uuid::new_v4().as_bytes())
}

/// A fresh nonce (256 bits from the OS, base64url): what a mount asks a
/// peer to sign at `_info`.
pub fn random_nonce() -> String {
    let mut n = [0u8; 32];
    getrandom_02::getrandom(&mut n).expect("the OS's randomness");
    b64(&n)
}

/// `key:<64 hex>` — the principal a key proves (spec/00's form).
pub fn principal_of(key: &VerifyingKey) -> String {
    format!("key:{}", hex(key.as_bytes()))
}

/// The key a `key:<64 hex>` principal names.
pub fn key_of(principal: &str) -> Option<VerifyingKey> {
    let h = principal.strip_prefix("key:")?;
    if h.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    VerifyingKey::from_bytes(&bytes).ok()
}

/// RFC 7638 thumbprint of an Ed25519 key (OKP, RFC 8037 §2):
/// base64url(sha256(`{"crv":"Ed25519","kty":"OKP","x":"…"}`)).
pub fn thumbprint(key: &VerifyingKey) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, b64(key.as_bytes()));
    b64(&Sha256::digest(canonical.as_bytes()))
}

/// base64url(sha256(token)) — a proof's `ath`.
pub fn token_hash(token: &str) -> String {
    b64(&Sha256::digest(token.as_bytes()))
}

// ------------------------------------------------------------------ keys

/// An Ed25519 key with its id (`key:<hex>`): a service's signing key, or a
/// peer's own. `Debug` never shows the seed.
#[derive(Clone)]
pub struct PeerKey {
    signing: SigningKey,
    kid: String,
}

impl std::fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerKey").field("kid", &self.kid).finish_non_exhaustive()
    }
}

impl PeerKey {
    /// A new key from the OS's randomness.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom_02::getrandom(&mut seed).expect("the OS's randomness");
        Self::from_seed(seed)
    }

    /// The key a 32-byte seed makes.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let kid = principal_of(&signing.verifying_key());
        Self { signing, kid }
    }

    /// The key in `path` (a 32-byte seed, raw or base64 — synapse's key
    /// file), made there (0600) when there is none. A file readable by
    /// others is refused.
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        let shown = path.display();
        if !path.exists() {
            let key = Self::generate();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            let text = base64::engine::general_purpose::STANDARD.encode(key.signing.to_bytes());
            write_private(path, text.as_bytes()).map_err(|e| format!("the key file {shown}: {e}"))?;
            return Ok(key);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).map_err(|e| format!("the key file {shown}: {e}"))?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!("the key file {shown} is readable by others (mode {:o}); a key is kept 0600", mode & 0o777));
            }
        }
        let raw = std::fs::read(path).map_err(|e| format!("the key file {shown}: {e}"))?;
        let text: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        let engines = [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::URL_SAFE,
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ];
        let seed: [u8; 32] = engines
            .iter()
            .find_map(|e| e.decode(&text).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()))
            .or_else(|| <[u8; 32]>::try_from(raw.as_slice()).ok())
            .ok_or_else(|| format!("the key file {shown} holds no 32-byte seed"))?;
        Ok(Self::from_seed(seed))
    }

    /// Its id: `key:<hex>` of its public half.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Its public half.
    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Its RFC 7638 thumbprint.
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.public())
    }

    /// Its public half as a JWK.
    pub fn jwk(&self) -> Jwk {
        Jwk::of(&self.public())
    }

    /// A compact JWS of `claims` under `header` (whose `alg` this sets).
    fn sign_compact(&self, mut header: Value, claims: &Value) -> String {
        header["alg"] = json!(ALG);
        let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let sig = self.signing.sign(input.as_bytes());
        format!("{input}.{}", b64(&sig.to_bytes()))
    }

    /// The `_info` key proof: a signature over
    /// `plexus-peer-key/v1\n<nonce>\n<backend>`, base64url.
    pub fn key_proof(&self, nonce: &str, backend: &str) -> String {
        b64(&self.signing.sign(format!("{KEY_PROOF_CONTEXT}\n{nonce}\n{backend}").as_bytes()).to_bytes())
    }
}

/// Check a peer's `_info` key proof: `key` (`key:<hex>`) signed `nonce` and
/// `backend` with [`PeerKey::key_proof`].
pub fn check_key_proof(key: &str, proof: &str, nonce: &str, backend: &str) -> Result<VerifyingKey, TokenError> {
    let vk = key_of(key).ok_or_else(|| TokenError::Malformed(format!("`{key}` is not an Ed25519 key")))?;
    let sig = signature_of(proof)?;
    vk.verify_strict(format!("{KEY_PROOF_CONTEXT}\n{nonce}\n{backend}").as_bytes(), &sig).map_err(|_| TokenError::Signature)?;
    Ok(vk)
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(bytes)
}

fn signature_of(s: &str) -> Result<Signature, TokenError> {
    let bytes = unb64(s)?;
    let arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| TokenError::Malformed("a signature is 64 bytes".into()))?;
    Ok(Signature::from_bytes(&arr))
}

/// A public key as a JWK (RFC 8037: `kty` OKP, `crv` Ed25519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    /// `key` as a signing JWK, its `kid` its principal.
    pub fn of(key: &VerifyingKey) -> Self {
        Self { kty: "OKP".into(), crv: "Ed25519".into(), x: b64(key.as_bytes()), kid: Some(principal_of(key)), alg: Some(ALG.into()), use_: Some("sig".into()) }
    }

    /// The key it holds, if it is an Ed25519 one.
    pub fn key(&self) -> Result<VerifyingKey, TokenError> {
        if self.kty != "OKP" || self.crv != "Ed25519" || self.alg.as_deref().is_some_and(|a| a != ALG) {
            return Err(TokenError::Algorithm(format!("a JWK of kty {} crv {}: only OKP Ed25519 (EdDSA)", self.kty, self.crv)));
        }
        let bytes = unb64(&self.x)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| TokenError::Malformed("an Ed25519 key is 32 bytes".into()))?;
        VerifyingKey::from_bytes(&arr).map_err(|_| TokenError::Malformed("not an Ed25519 point".into()))
    }
}

/// A JWK Set (RFC 7517 §5): what `dyn.jwks` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

// ------------------------------------------------------------------ claims

/// One actor of the chain (RFC 8693 §4.1), the prior ones nested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<Actor>>,
}

impl Actor {
    /// The chain, nearest first.
    pub fn chain(&self) -> Vec<String> {
        let mut out = vec![self.sub.clone()];
        let mut next = self.act.as_deref();
        while let Some(a) = next {
            out.push(a.sub.clone());
            next = a.act.as_deref();
        }
        out
    }

    /// `sub` acting, after `prior`.
    pub fn after(sub: impl Into<String>, prior: Option<Actor>) -> Self {
        Self { sub: sub.into(), act: prior.map(Box::new) }
    }
}

/// The key a token is bound to (RFC 7800 `cnf`, RFC 9449 `jkt`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    pub jkt: String,
}

/// A peer token's claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    pub aud: String,
    /// `grant@scope` entries; on the wire one space-separated string
    /// (RFC 8693 §4.2).
    #[serde(with = "space_separated")]
    pub scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Cnf>,
    pub call: String,
    pub method: String,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
}

mod space_separated {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[String], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.join(" "))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
        let s = String::deserialize(d)?;
        Ok(s.split(' ').filter(|x| !x.is_empty()).map(str::to_string).collect())
    }
}

impl PeerClaims {
    /// The actor chain, nearest first (empty when nobody acted).
    pub fn actors(&self) -> Vec<String> {
        self.act.as_ref().map(Actor::chain).unwrap_or_default()
    }

    /// The scopes the token holds `grant` on (`["*"]`, `["MENGER"]`, `[]`).
    pub fn scopes_for(&self, grant: &str) -> Vec<String> {
        self.scope.iter().filter_map(|e| e.rsplit_once('@').filter(|(g, _)| *g == grant).map(|(_, s)| s.to_string())).collect()
    }
}

/// `grant@scope` split.
fn entry(e: &str) -> Option<(&str, &str)> {
    e.rsplit_once('@')
}

/// Whether `inner`'s scope lies within `outer`'s (`*` holds every one).
fn scope_within(inner: &str, outer: &str) -> bool {
    outer == "*" || inner == outer
}

/// Whether every entry of `inner` is held by `outer`: the same grant, on
/// the same scope or within one `outer` holds (`*`).
pub fn is_within(inner: &[String], outer: &[String]) -> bool {
    inner.iter().all(|i| match entry(i) {
        Some((g, s)) => outer.iter().filter_map(|o| entry(o)).any(|(og, os)| og == g && scope_within(s, os)),
        None => false,
    })
}

/// The scope an exchange may give: `requested` (all of `presented` when
/// `None`), each entry kept only where `presented` holds it — narrowed to
/// the inner scope, never widened. RFC 8693 §2.1 downscoping.
pub fn narrow(requested: Option<&[String]>, presented: &[String]) -> Vec<String> {
    let Some(req) = requested else { return presented.to_vec() };
    let mut out: Vec<String> = Vec::new();
    for r in req {
        let Some((g, s)) = entry(r) else { continue };
        for (pg, ps) in presented.iter().filter_map(|p| entry(p)) {
            if pg != g {
                continue;
            }
            let kept = if scope_within(s, ps) {
                Some(s)
            } else if scope_within(ps, s) {
                Some(ps)
            } else {
                None
            };
            if let Some(k) = kept {
                let e = format!("{g}@{k}");
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
    }
    out
}

/// The scope a forwarded call's token holds (D3: the caller's reach ∩ the
/// peer's needs ∩ consent): the forwarded grant on each scope the call was
/// admitted on (`reach`, `["*"]` when everywhere), and each need's grant on
/// each scope both its consent and the reach hold. Never a scope the reach
/// does not hold.
pub fn mint_scope(forwarded: Option<&str>, reach: &[String], needs: &[(String, Vec<String>)]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |g: &str, s: &str| {
        let e = format!("{g}@{s}");
        if !out.contains(&e) {
            out.push(e);
        }
    };
    let everywhere = reach.iter().any(|r| r == "*");
    if let Some(g) = forwarded {
        for r in reach {
            push(g, r);
        }
    }
    for (g, consented) in needs {
        let any = consented.iter().any(|c| c == "*");
        let scopes: Vec<&String> = match (everywhere, any) {
            (true, _) => consented.iter().collect(),
            (false, true) => reach.iter().collect(),
            (false, false) => consented.iter().filter(|c| reach.contains(c)).collect(),
        };
        for s in scopes {
            push(g, s);
        }
    }
    out
}

/// DYNAUTH-6 (RFC 8693): the scope of the token for an onward call — one a
/// peer made back through its service under `presented`, which reaches
/// another peer. Never wider than `presented`: each need of the next peer
/// only where `presented` holds the same grant ([`narrow`]); the forwarded
/// grant (the next peer's terms) only on the scopes where `presented` holds
/// `admitted` — the grant the service admitted the onward call on, in its
/// own terms (`dyn.{peer}`). Within `reach` as [`mint_scope`] is.
pub fn onward_scope(presented: &PeerClaims, admitted: Option<&str>, forwarded: Option<&str>, reach: &[String], needs: &[(String, Vec<String>)]) -> Vec<String> {
    let mut out = narrow(Some(&mint_scope(None, reach, needs)), &presented.scope);
    if let (Some(a), Some(f)) = (admitted, forwarded) {
        for held in presented.scopes_for(a) {
            for r in reach {
                let s = if scope_within(r, &held) {
                    r.as_str()
                } else if scope_within(&held, r) {
                    held.as_str()
                } else {
                    continue;
                };
                let e = format!("{f}@{s}");
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ errors

/// Why a token or a proof is refused. Says what, never the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Malformed(String),
    /// `alg` not EdDSA, or a key of another kind.
    Algorithm(String),
    /// `typ` not the one expected.
    Type(String),
    /// `kid` names no key the verifier trusts.
    UnknownKey(String),
    Signature,
    /// `aud` is another's.
    Audience { want: String, got: String },
    Expired,
    /// `iat` in the future, past the skew.
    NotYet,
    /// `exp − iat` past [`MAX_LIFETIME`].
    Lifetime(u64),
    Replayed,
    /// Presented for another call or method than it names.
    Binding(String),
    /// A proof of possession missing or wrong.
    Proof(String),
    /// A scope that is not within the one it must be.
    Scope(String),
    /// The issuer refuses to mint (revoked, no caller).
    Refused(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(w) => write!(f, "a malformed token: {w}"),
            Self::Algorithm(w) => write!(f, "algorithm refused: {w}"),
            Self::Type(w) => write!(f, "type refused: {w}"),
            Self::UnknownKey(k) => write!(f, "signed by a key not trusted here ({k})"),
            Self::Signature => write!(f, "the signature does not verify"),
            Self::Audience { want, got } => write!(f, "addressed to {got}, not to {want}"),
            Self::Expired => write!(f, "expired"),
            Self::NotYet => write!(f, "issued in the future"),
            Self::Lifetime(s) => write!(f, "lives {s} s, past {} s", MAX_LIFETIME.as_secs()),
            Self::Replayed => write!(f, "already used (replayed)"),
            Self::Binding(w) => write!(f, "presented for another call: {w}"),
            Self::Proof(w) => write!(f, "no valid proof of possession: {w}"),
            Self::Scope(w) => write!(f, "scope refused: {w}"),
            Self::Refused(w) => write!(f, "{w}"),
        }
    }
}

impl std::error::Error for TokenError {}

// ------------------------------------------------------------------ JWS

struct Parsed {
    header: Value,
    payload: Vec<u8>,
    input: String,
    sig: Signature,
}

/// Split and decode a compact JWS; the algorithm checked here, before
/// anything else is believed: `alg` must be exactly `EdDSA` (`none`,
/// `HS256`, anything else refused — the verifier chooses the algorithm,
/// never the token), and no `jku`/`x5u`/`crit` is honoured.
fn parse(token: &str, typ: &str) -> Result<Parsed, TokenError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(TokenError::Malformed("a compact JWS has three parts".into()));
    };
    let header: Value = serde_json::from_slice(&unb64(h)?).map_err(|_| TokenError::Malformed("the header is not JSON".into()))?;
    match header.get("alg").and_then(Value::as_str) {
        Some(ALG) => {}
        other => return Err(TokenError::Algorithm(format!("alg {:?}: only EdDSA", other.unwrap_or("(none)")))),
    }
    if header.get("crit").is_some() {
        return Err(TokenError::Malformed("`crit` is not understood here".into()));
    }
    match header.get("typ").and_then(Value::as_str) {
        Some(t) if t.eq_ignore_ascii_case(typ) => {}
        other => return Err(TokenError::Type(format!("typ {:?}, not {typ}", other.unwrap_or("(none)")))),
    }
    Ok(Parsed { header, payload: unb64(p)?, input: format!("{h}.{p}"), sig: signature_of(s)? })
}

// ------------------------------------------------------------------ verify

/// What a token must also say to be taken for this presentation.
#[derive(Debug, Clone, Default)]
pub struct Expect<'a> {
    /// The forwarded call's id (`hop.call`).
    pub call: Option<&'a str>,
    /// The method it is presented for (in the verifier's terms).
    pub method: Option<&'a str>,
}

/// Checks tokens addressed to one audience, from the issuers it trusts,
/// each `jti` once.
pub struct Verifier {
    audience: String,
    issuers: RwLock<BTreeMap<String, VerifyingKey>>,
    seen: Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier").field("audience", &self.audience).field("issuers", &self.issuers.read().unwrap().keys().collect::<Vec<_>>()).finish()
    }
}

impl Verifier {
    /// A verifier for tokens addressed to `audience`, trusting `jwks`.
    pub fn new(audience: impl Into<String>, jwks: &Jwks) -> Result<Self, TokenError> {
        let v = Self { audience: audience.into(), issuers: RwLock::default(), seen: Mutex::default() };
        v.trust(jwks)?;
        Ok(v)
    }

    /// The audience it takes.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Trust exactly `jwks` from now (a rotation: the old key goes once the
    /// issuer's JWKS drops it).
    pub fn trust(&self, jwks: &Jwks) -> Result<(), TokenError> {
        let mut keys = BTreeMap::new();
        for k in &jwks.keys {
            let vk = k.key()?;
            keys.insert(k.kid.clone().unwrap_or_else(|| principal_of(&vk)), vk);
        }
        *self.issuers.write().unwrap() = keys;
        Ok(())
    }

    /// Verify `token` now.
    pub fn verify(&self, token: &str, expect: &Expect<'_>) -> Result<PeerClaims, TokenError> {
        self.verify_at(token, expect, now())
    }

    /// Verify `token` as of `now` (seconds since the epoch).
    pub fn verify_at(&self, token: &str, expect: &Expect<'_>, now: u64) -> Result<PeerClaims, TokenError> {
        let parsed = parse(token, TOKEN_TYP)?;
        let kid = parsed.header.get("kid").and_then(Value::as_str).unwrap_or_default().to_string();
        let key = self.issuers.read().unwrap().get(&kid).copied().ok_or(TokenError::UnknownKey(kid.clone()))?;
        key.verify_strict(parsed.input.as_bytes(), &parsed.sig).map_err(|_| TokenError::Signature)?;
        let claims: PeerClaims = serde_json::from_slice(&parsed.payload).map_err(|e| TokenError::Malformed(format!("its claims: {e}")))?;
        if claims.iss != kid {
            return Err(TokenError::Malformed("`iss` is not the key that signed it".into()));
        }
        check_times(&claims, now)?;
        if claims.aud != self.audience {
            return Err(TokenError::Audience { want: self.audience.clone(), got: claims.aud });
        }
        if let Some(call) = expect.call.filter(|c| *c != claims.call) {
            return Err(TokenError::Binding(format!("it names call {}, presented under {call}", claims.call)));
        }
        if let Some(method) = expect.method.filter(|m| *m != claims.method) {
            return Err(TokenError::Binding(format!("it names {}, presented for {method}", claims.method)));
        }
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, exp| *exp + SKEW.as_secs() >= now);
        if seen.insert(claims.jti.clone(), claims.exp).is_some() {
            return Err(TokenError::Replayed);
        }
        Ok(claims)
    }

    /// `jti`s held now (the replay cache's size).
    pub fn held(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

fn check_times(claims: &PeerClaims, now: u64) -> Result<(), TokenError> {
    if claims.exp < claims.iat || claims.exp - claims.iat > MAX_LIFETIME.as_secs() {
        return Err(TokenError::Lifetime(claims.exp.saturating_sub(claims.iat)));
    }
    if claims.iat > now + SKEW.as_secs() {
        return Err(TokenError::NotYet);
    }
    if now > claims.exp + SKEW.as_secs() {
        return Err(TokenError::Expired);
    }
    Ok(())
}

// ------------------------------------------------------------------ proof

/// A proof of possession by `key` for presenting `token` for `method`
/// under `call` (see the module docs).
pub fn prove(key: &PeerKey, token: &str, method: &str, call: &str) -> String {
    prove_at(key, token, method, call, now())
}

/// [`prove`] as of `iat`.
pub fn prove_at(key: &PeerKey, token: &str, method: &str, call: &str, iat: u64) -> String {
    let header = json!({ "typ": PROOF_TYP, "jwk": key.jwk() });
    let claims = json!({ "ath": token_hash(token), "jti": random_id(), "method": method, "call": call, "iat": iat });
    key.sign_compact(header, &claims)
}

/// The proofs a presenter's side has seen, each once (by its `jti`, kept
/// for twice the skew).
#[derive(Debug, Default)]
pub struct ProofCache(Mutex<HashMap<String, u64>>);

/// Check `proof` for presenting `token` (whose claims are `claims`) for
/// `method` under `call`, as of `now`: signed by the key `claims.cnf.jkt`
/// names, over this token, method and call, fresh, and not seen before.
pub fn check_proof(proof: &str, token: &str, claims: &PeerClaims, method: &str, call: &str, now: u64, seen: &ProofCache) -> Result<(), TokenError> {
    let jkt = claims.cnf.as_ref().map(|c| c.jkt.as_str()).ok_or_else(|| TokenError::Proof("the token is bound to no key".into()))?;
    let parsed = parse(proof, PROOF_TYP).map_err(|e| TokenError::Proof(e.to_string()))?;
    let jwk: Jwk = parsed.header.get("jwk").cloned().and_then(|j| serde_json::from_value(j).ok()).ok_or_else(|| TokenError::Proof("no `jwk` in its header".into()))?;
    let key = jwk.key().map_err(|e| TokenError::Proof(e.to_string()))?;
    if thumbprint(&key) != jkt {
        return Err(TokenError::Proof("signed by another key than the token is bound to".into()));
    }
    key.verify_strict(parsed.input.as_bytes(), &parsed.sig).map_err(|_| TokenError::Proof("its signature does not verify".into()))?;
    let c: Value = serde_json::from_slice(&parsed.payload).map_err(|_| TokenError::Proof("its claims are not JSON".into()))?;
    let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default();
    if s("ath") != token_hash(token) {
        return Err(TokenError::Proof("made for another token".into()));
    }
    if s("method") != method || s("call") != call {
        return Err(TokenError::Proof(format!("made for {} under {}, presented for {method} under {call}", s("method"), s("call"))));
    }
    let iat = c.get("iat").and_then(Value::as_u64).unwrap_or_default();
    if iat + SKEW.as_secs() < now || iat > now + SKEW.as_secs() {
        return Err(TokenError::Proof("not fresh (iat past the skew)".into()));
    }
    let jti = s("jti");
    if jti.is_empty() {
        return Err(TokenError::Proof("no `jti`".into()));
    }
    let mut seen = seen.0.lock().unwrap();
    seen.retain(|_, t| *t + 2 * SKEW.as_secs() >= now);
    if seen.insert(jti.to_string(), iat).is_some() {
        return Err(TokenError::Proof("replayed".into()));
    }
    Ok(())
}

// ------------------------------------------------------------------ audit

/// What was done with a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    Mint,
    Exchange,
}

/// One audit record (TM-7): who acted through whom, for what. Never the
/// token, a signature or a proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub kind: AuditKind,
    pub iss: String,
    pub sub: String,
    /// The actor chain, nearest first.
    pub act: Vec<String>,
    pub aud: String,
    pub scope: Vec<String>,
    pub call: String,
    pub jti: String,
    pub exp: u64,
    pub method: String,
}

impl AuditRecord {
    fn of(kind: AuditKind, c: &PeerClaims) -> Self {
        Self { kind, iss: c.iss.clone(), sub: c.sub.clone(), act: c.actors(), aud: c.aud.clone(), scope: c.scope.clone(), call: c.call.clone(), jti: c.jti.clone(), exp: c.exp, method: c.method.clone() }
    }
}

/// Where audit records go besides `tracing` (PRIVACY-1's sink, when it is).
pub trait TokenAudit: Send + Sync {
    fn record(&self, r: &AuditRecord);
}

fn audit(sink: Option<&Arc<dyn TokenAudit>>, r: AuditRecord) {
    tracing::info!(
        target: "plexus::audit",
        kind = ?r.kind, iss = %r.iss, sub = %r.sub, act = ?r.act, aud = %r.aud,
        scope = %r.scope.join(" "), call = %r.call, jti = %r.jti, exp = r.exp, method = %r.method,
        "peer token"
    );
    if let Some(s) = sink {
        s.record(&r);
    }
}

// ------------------------------------------------------------------ issue

/// What one forwarded call's token is minted from.
#[derive(Debug, Clone)]
pub struct MintRequest {
    /// The original caller.
    pub sub: String,
    /// The peer: its key (`key:<hex>`), or `None` for a child on the
    /// issuer's own pipe (`aud` `pipe:<name>`, no `cnf`).
    pub peer_key: Option<String>,
    /// The mount's name (a pipe child's audience).
    pub name: String,
    pub scope: Vec<String>,
    pub call: String,
    pub method: String,
    /// When this mint is an exchange: the token presented, already
    /// verified, and who presented it (its audience).
    pub presented: Option<PeerClaims>,
}

/// A service's token issuer: its signing key (rotatable, the old one kept
/// in the JWKS for one token lifetime and the skew), the lifetime it
/// mints, and the audit sink.
pub struct TokenIssuer {
    key: RwLock<PeerKey>,
    retired: Mutex<Vec<(PeerKey, u64)>>,
    ttl: Duration,
    sink: Option<Arc<dyn TokenAudit>>,
}

impl std::fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenIssuer").field("kid", &self.kid()).field("ttl", &self.ttl).finish_non_exhaustive()
    }
}

impl TokenIssuer {
    /// An issuer signing with `key`, minting tokens of [`MAX_LIFETIME`].
    pub fn new(key: PeerKey) -> Self {
        Self { key: RwLock::new(key), retired: Mutex::default(), ttl: MAX_LIFETIME, sink: None }
    }

    /// Tokens of `ttl` (at most [`MAX_LIFETIME`]).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl.min(MAX_LIFETIME);
        self
    }

    /// Audit records also to `sink`.
    pub fn with_audit(mut self, sink: Arc<dyn TokenAudit>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The signing key's id now.
    pub fn kid(&self) -> String {
        self.key.read().unwrap().kid().to_string()
    }

    /// The lifetime it mints.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The keys a peer verifies with: the current one, and each retired one
    /// while a token it signed may still be presented.
    pub fn jwks(&self) -> Jwks {
        let now = now();
        let mut retired = self.retired.lock().unwrap();
        retired.retain(|(_, until)| *until >= now);
        let mut keys = vec![self.key.read().unwrap().jwk()];
        keys.extend(retired.iter().map(|(k, _)| k.jwk()));
        Jwks { keys }
    }

    /// Sign with `new` from now; the old key stays in [`Self::jwks`] for one
    /// token lifetime and the skew, then goes.
    pub fn rotate(&self, new: PeerKey) -> String {
        let old = std::mem::replace(&mut *self.key.write().unwrap(), new);
        let until = now() + self.ttl.as_secs() + SKEW.as_secs();
        self.retired.lock().unwrap().push((old, until));
        self.kid()
    }

    /// Mint one forwarded call's token (an exchange when `req.presented`).
    pub fn mint(&self, req: MintRequest) -> Result<(String, PeerClaims), TokenError> {
        self.mint_at(req, now())
    }

    /// [`Self::mint`] as of `now`.
    pub fn mint_at(&self, req: MintRequest, now: u64) -> Result<(String, PeerClaims), TokenError> {
        let key = self.key.read().unwrap().clone();
        let (aud, cnf) = match &req.peer_key {
            Some(k) => {
                let vk = key_of(k).ok_or_else(|| TokenError::Malformed(format!("`{k}` is not an Ed25519 key")))?;
                (k.clone(), Some(Cnf { jkt: thumbprint(&vk) }))
            }
            None => (format!("pipe:{}", req.name), None),
        };
        let (sub, act, scope, kind) = match &req.presented {
            None => (req.sub.clone(), Some(Actor::after(key.kid(), None)), req.scope.clone(), AuditKind::Mint),
            Some(p) => {
                // RFC 8693: the subject stays; the presenter joins the
                // chain. The scope is the caller's to narrow (`exchange`,
                // `onward_scope`): never wider than the presented one's.
                let prior = Actor::after(p.aud.clone(), p.act.clone());
                (p.sub.clone(), Some(Actor::after(key.kid(), Some(prior))), req.scope.clone(), AuditKind::Exchange)
            }
        };
        let claims = PeerClaims {
            iss: key.kid().to_string(),
            sub,
            act,
            aud,
            scope,
            cnf,
            call: req.call,
            method: req.method,
            jti: random_id(),
            iat: now,
            exp: now + self.ttl.as_secs(),
        };
        let token = key.sign_compact(json!({ "typ": TOKEN_TYP, "kid": key.kid() }), &serde_json::to_value(&claims).unwrap_or_default());
        audit(self.sink.as_ref(), AuditRecord::of(kind, &claims));
        Ok((token, claims))
    }

    /// RFC 8693 token exchange, as a method answers it: `subject` (a token
    /// this issuer minted, presented by its audience with `proof` when it is
    /// key-bound) becomes a token for `audience` (`peer_key`, a name for a
    /// pipe), its scope `requested` narrowed by the presented one.
    #[allow(clippy::too_many_arguments)]
    pub fn exchange(&self, subject: &str, proof: Option<&str>, name: &str, peer_key: Option<String>, requested: Option<&[String]>, call: &str, method: &str, seen: &ProofCache) -> Result<(String, PeerClaims), TokenError> {
        let presented = self.verify_own(subject)?;
        // A token bound to no key (a pipe's) is its pipe's alone: it is
        // never exchanged by whoever holds its bytes.
        if presented.cnf.is_none() {
            return Err(TokenError::Proof("a token bound to no key (a pipe's) is not exchanged".into()));
        }
        let proof = proof.ok_or_else(|| TokenError::Proof("a key-bound token is exchanged with a proof".into()))?;
        check_proof(proof, subject, &presented, EXCHANGE, &presented.call, now(), seen)?;
        let scope = narrow(requested, &presented.scope);
        self.mint(MintRequest { sub: presented.sub.clone(), peer_key, name: name.into(), scope, call: call.into(), method: method.into(), presented: Some(presented) })
    }

    /// A token this issuer minted (any audience), signature and times
    /// checked — what the issuer reads back when a peer presents it.
    pub fn verify_own(&self, token: &str) -> Result<PeerClaims, TokenError> {
        let parsed = parse(token, TOKEN_TYP)?;
        let kid = parsed.header.get("kid").and_then(Value::as_str).unwrap_or_default();
        let jwks = self.jwks();
        let key = jwks.keys.iter().find(|k| k.kid.as_deref() == Some(kid)).ok_or_else(|| TokenError::UnknownKey(kid.to_string()))?.key()?;
        key.verify_strict(parsed.input.as_bytes(), &parsed.sig).map_err(|_| TokenError::Signature)?;
        let claims: PeerClaims = serde_json::from_slice(&parsed.payload).map_err(|e| TokenError::Malformed(format!("its claims: {e}")))?;
        check_times(&claims, now())?;
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(peer: &PeerKey) -> MintRequest {
        MintRequest {
            sub: "key:caller".into(),
            peer_key: Some(peer.kid().to_string()),
            name: "w".into(),
            scope: vec!["weather.forecast@*".into(), "shop.items@MENGER".into()],
            call: "call-1".into(),
            method: "far.weather.forecast".into(),
            presented: None,
        }
    }

    fn header_of(token: &str) -> Value {
        serde_json::from_slice(&unb64(token.split('.').next().unwrap()).unwrap()).unwrap()
    }

    fn claims_part(token: &str) -> Value {
        serde_json::from_slice(&unb64(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
    }

    /// Re-sign `token`'s parts as given — a forger with some key.
    fn forge(key: &PeerKey, header: Value, claims: Value) -> String {
        let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        format!("{input}.{}", b64(&key.signing.sign(input.as_bytes()).to_bytes()))
    }

    #[test]
    fn a_token_signs_and_verifies() {
        let (host, peer) = (PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host.clone());
        let (token, minted) = issuer.mint(req(&peer)).unwrap();
        let h = header_of(&token);
        assert_eq!((h["alg"].as_str(), h["typ"].as_str(), h["kid"].as_str()), (Some("EdDSA"), Some(TOKEN_TYP), Some(host.kid())));
        let c = claims_part(&token);
        assert_eq!(c["scope"], "weather.forecast@* shop.items@MENGER", "space-separated on the wire");
        assert_eq!(c["cnf"]["jkt"], peer.thumbprint());
        assert_eq!(c["act"], json!({ "sub": host.kid() }));
        assert!(minted.exp - minted.iat <= 60);
        let v = Verifier::new(peer.kid(), &issuer.jwks()).unwrap();
        let got = v.verify(&token, &Expect { call: Some("call-1"), method: Some("far.weather.forecast") }).unwrap();
        assert_eq!(got, minted);
        assert_eq!(got.scopes_for("shop.items"), ["MENGER"]);
    }

    #[test]
    fn a_token_for_another_audience_is_refused() {
        let (host, a, b) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let (for_a, _) = issuer.mint(req(&a)).unwrap();
        let at_b = Verifier::new(b.kid(), &issuer.jwks()).unwrap();
        assert!(matches!(at_b.verify(&for_a, &Expect::default()), Err(TokenError::Audience { .. })));
    }

    #[test]
    fn an_expired_or_future_or_long_token_is_refused() {
        let (host, peer) = (PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host.clone());
        let v = Verifier::new(peer.kid(), &issuer.jwks()).unwrap();
        let t0 = now();
        let (old, _) = issuer.mint_at(req(&peer), t0 - 200).unwrap();
        assert_eq!(v.verify_at(&old, &Expect::default(), t0), Err(TokenError::Expired));
        // Within the skew past `exp`, still taken; past it, not.
        let (t, c) = issuer.mint_at(req(&peer), t0).unwrap();
        assert!(v.verify_at(&t, &Expect::default(), c.exp + 29).is_ok());
        let (t, c) = issuer.mint_at(req(&peer), t0).unwrap();
        assert_eq!(v.verify_at(&t, &Expect::default(), c.exp + 31), Err(TokenError::Expired));
        let (future, _) = issuer.mint_at(req(&peer), t0 + 120).unwrap();
        assert_eq!(v.verify_at(&future, &Expect::default(), t0), Err(TokenError::NotYet));
        // A token that claims to live past 60 s, even signed by the host.
        let mut c = claims_part(&future);
        c["iat"] = json!(t0);
        c["exp"] = json!(t0 + 3600);
        let long = forge(&host, json!({ "alg": "EdDSA", "typ": TOKEN_TYP, "kid": host.kid() }), c);
        assert_eq!(v.verify_at(&long, &Expect::default(), t0), Err(TokenError::Lifetime(3600)));
    }

    #[test]
    fn a_replayed_jti_is_refused() {
        let (host, peer) = (PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let v = Verifier::new(peer.kid(), &issuer.jwks()).unwrap();
        let (t, _) = issuer.mint(req(&peer)).unwrap();
        assert!(v.verify(&t, &Expect::default()).is_ok());
        assert_eq!(v.verify(&t, &Expect::default()), Err(TokenError::Replayed));
        assert_eq!(v.held(), 1);
    }

    #[test]
    fn a_token_presented_for_another_call_or_method_is_refused() {
        let (host, peer) = (PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let v = Verifier::new(peer.kid(), &issuer.jwks()).unwrap();
        let (t, _) = issuer.mint(req(&peer)).unwrap();
        assert!(matches!(v.verify(&t, &Expect { call: Some("call-2"), method: None }), Err(TokenError::Binding(_))));
        let (t, _) = issuer.mint(req(&peer)).unwrap();
        assert!(matches!(v.verify(&t, &Expect { call: None, method: Some("far.weather.secret") }), Err(TokenError::Binding(_))));
    }

    #[test]
    fn alg_confusion_and_forgeries_are_refused() {
        let (host, peer, other) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host.clone());
        let v = Verifier::new(peer.kid(), &issuer.jwks()).unwrap();
        let (t, _) = issuer.mint(req(&peer)).unwrap();
        let (h, c) = (header_of(&t), claims_part(&t));
        let parts: Vec<&str> = t.split('.').collect();
        // `alg: none`, no signature.
        let mut none = h.clone();
        none["alg"] = json!("none");
        let unsigned = format!("{}.{}.", b64(none.to_string().as_bytes()), parts[1]);
        assert!(matches!(v.verify(&unsigned, &Expect::default()), Err(TokenError::Algorithm(_))), "alg none");
        // HS256 "signed" with the public key as an HMAC secret: refused on
        // its alg before any key is looked at.
        let mut hs = h.clone();
        hs["alg"] = json!("HS256");
        let hs_token = format!("{}.{}.{}", b64(hs.to_string().as_bytes()), parts[1], parts[2]);
        assert!(matches!(v.verify(&hs_token, &Expect::default()), Err(TokenError::Algorithm(_))), "HS256");
        // No typ, another typ (a proof passed off as a token).
        let mut typ = h.clone();
        typ["typ"] = json!(PROOF_TYP);
        assert!(matches!(v.verify(&forge(&host, typ, c.clone()), &Expect::default()), Err(TokenError::Type(_))));
        // Signed by another key under the host's kid.
        assert_eq!(v.verify(&forge(&other, h.clone(), c.clone()), &Expect::default()), Err(TokenError::Signature));
        // Signed by another key under its own kid: not trusted.
        let mut own = h.clone();
        own["kid"] = json!(other.kid());
        let mut c2 = c.clone();
        c2["iss"] = json!(other.kid());
        assert!(matches!(v.verify(&forge(&other, own, c2), &Expect::default()), Err(TokenError::UnknownKey(_))));
        // A claim changed after signing.
        let mut wider = c.clone();
        wider["scope"] = json!("admin@*");
        let tampered = format!("{}.{}.{}", parts[0], b64(wider.to_string().as_bytes()), parts[2]);
        assert_eq!(v.verify(&tampered, &Expect::default()), Err(TokenError::Signature));
        // `crit` and garbage.
        let mut crit = h.clone();
        crit["crit"] = json!(["exp"]);
        assert!(matches!(v.verify(&forge(&host, crit, c), &Expect::default()), Err(TokenError::Malformed(_))));
        assert!(matches!(v.verify("a.b", &Expect::default()), Err(TokenError::Malformed(_))));
        // A JWKS offering another kind of key is refused outright.
        let rsa = Jwks { keys: vec![Jwk { kty: "RSA".into(), crv: String::new(), x: String::new(), kid: None, alg: Some("RS256".into()), use_: None }] };
        assert!(matches!(Verifier::new(peer.kid(), &rsa), Err(TokenError::Algorithm(_))));
    }

    #[test]
    fn the_proof_of_possession_is_the_bound_key_s_for_this_call() {
        let (host, peer, thief) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let (t, c) = issuer.mint(req(&peer)).unwrap();
        let seen = ProofCache::default();
        let n = now();
        let p = prove(&peer, &t, "shop.items", "call-1");
        assert_eq!(check_proof(&p, &t, &c, "shop.items", "call-1", n, &seen), Ok(()));
        assert!(matches!(check_proof(&p, &t, &c, "shop.items", "call-1", n, &seen), Err(TokenError::Proof(w)) if w.contains("replayed")));
        // The thief has the token's bytes, not the peer's key.
        let stolen = prove(&thief, &t, "shop.items", "call-1");
        assert!(matches!(check_proof(&stolen, &t, &c, "shop.items", "call-1", n, &seen), Err(TokenError::Proof(w)) if w.contains("another key")));
        // A proof for another method, call or token.
        let p = prove(&peer, &t, "shop.items", "call-1");
        assert!(check_proof(&p, &t, &c, "shop.secret", "call-1", n, &seen).is_err());
        let p = prove(&peer, &t, "shop.items", "call-9");
        assert!(check_proof(&p, &t, &c, "shop.items", "call-1", n, &seen).is_err());
        let (t2, _) = issuer.mint(req(&peer)).unwrap();
        let p = prove(&peer, &t2, "shop.items", "call-1");
        assert!(matches!(check_proof(&p, &t, &c, "shop.items", "call-1", n, &seen), Err(TokenError::Proof(w)) if w.contains("another token")));
        // Stale.
        let p = prove_at(&peer, &t, "shop.items", "call-1", n - 120);
        assert!(matches!(check_proof(&p, &t, &c, "shop.items", "call-1", n, &seen), Err(TokenError::Proof(w)) if w.contains("fresh")));
        // A pipe's token is bound to no key: no proof can be checked for it.
        let pipe = issuer.mint(MintRequest { peer_key: None, ..req(&peer) }).unwrap().1;
        assert_eq!(pipe.aud, "pipe:w");
        assert!(pipe.cnf.is_none());
    }

    #[test]
    fn a_key_proof_at_info_is_checked() {
        let peer = PeerKey::generate();
        let p = peer.key_proof("n0nce", "far");
        assert!(check_key_proof(peer.kid(), &p, "n0nce", "far").is_ok());
        assert_eq!(check_key_proof(peer.kid(), &p, "other", "far").map(|_| ()), Err(TokenError::Signature));
        assert_eq!(check_key_proof(PeerKey::generate().kid(), &p, "n0nce", "far").map(|_| ()), Err(TokenError::Signature));
    }

    #[test]
    fn an_exchange_narrows_and_never_widens() {
        let (host, a, b) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host.clone());
        let (t, c) = issuer.mint(req(&a)).unwrap();
        let seen = ProofCache::default();
        // No proof: refused (the token is bound to a's key).
        assert!(matches!(issuer.exchange(&t, None, "b", Some(b.kid().into()), None, "call-2", "far.x", &seen), Err(TokenError::Proof(_))));
        // Asking for more than was presented: only the overlap is given.
        let ask = vec!["shop.items@*".to_string(), "auth.grant@*".to_string(), "weather.forecast@LISBON".to_string()];
        let proof = prove(&a, &t, "exchange", &c.call);
        let (t2, c2) = issuer.exchange(&t, Some(&proof), "b", Some(b.kid().into()), Some(&ask), "call-2", "far.x", &seen).unwrap();
        assert_eq!(c2.scope, ["shop.items@MENGER", "weather.forecast@LISBON"]);
        assert!(is_within(&c2.scope, &c.scope));
        assert_eq!(c2.sub, c.sub, "the subject survives every hop");
        assert_eq!(c2.actors(), [host.kid().to_string(), a.kid().to_string(), host.kid().to_string()], "act names each hop, nearest first");
        assert_eq!(c2.aud, b.kid());
        let at_b = Verifier::new(b.kid(), &issuer.jwks()).unwrap();
        assert_eq!(at_b.verify(&t2, &Expect::default()).unwrap(), c2);
        // A pipe's token (bound to no key) is never exchanged.
        let (pipe, _) = issuer.mint(MintRequest { peer_key: None, ..req(&a) }).unwrap();
        assert!(matches!(issuer.exchange(&pipe, None, "b", Some(b.kid().into()), None, "c", "m", &seen), Err(TokenError::Proof(w)) if w.contains("pipe")));
        // Nothing asked: the presented scope, no wider.
        let proof = prove(&a, &t, "exchange", &c.call);
        let (_, c3) = issuer.exchange(&t, Some(&proof), "b", Some(b.kid().into()), None, "call-3", "far.x", &seen).unwrap();
        assert_eq!(c3.scope, c.scope);
        // narrow, exhaustively over a small lattice.
        let all = ["g@*", "g@A", "g@B", "h@*", "h@A"];
        for p in 0..(1 << all.len()) {
            let presented: Vec<String> = (0..all.len()).filter(|i| p & (1 << i) != 0).map(|i| all[i].to_string()).collect();
            for r in 0..(1 << all.len()) {
                let requested: Vec<String> = (0..all.len()).filter(|i| r & (1 << i) != 0).map(|i| all[i].to_string()).collect();
                let got = narrow(Some(&requested), &presented);
                assert!(is_within(&got, &presented), "{requested:?} from {presented:?} gave {got:?}");
            }
        }
    }

    #[test]
    fn a_rotated_key_verifies_for_one_lifetime_then_goes() {
        let (old, new, peer) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(old.clone());
        let (t_old, _) = issuer.mint(req(&peer)).unwrap();
        issuer.rotate(new.clone());
        let jwks = issuer.jwks();
        assert_eq!(jwks.keys.iter().map(|k| k.kid.clone().unwrap()).collect::<Vec<_>>(), [new.kid().to_string(), old.kid().to_string()]);
        let v = Verifier::new(peer.kid(), &jwks).unwrap();
        assert!(v.verify(&t_old, &Expect::default()).is_ok(), "an old token still verifies while it lives");
        let (t_new, c) = issuer.mint(req(&peer)).unwrap();
        assert_eq!(c.iss, new.kid());
        assert!(v.verify(&t_new, &Expect::default()).is_ok());
        // Once the old key leaves the JWKS, a verifier that refreshed refuses it.
        issuer.retired.lock().unwrap().clear();
        v.trust(&issuer.jwks()).unwrap();
        let (t, _) = (t_old, ());
        assert!(matches!(v.verify(&t, &Expect::default()), Err(TokenError::UnknownKey(_)) | Err(TokenError::Replayed)));
    }

    #[test]
    fn every_mint_and_exchange_is_audited_without_a_secret() {
        #[derive(Default)]
        struct Sink(Mutex<Vec<AuditRecord>>);
        impl TokenAudit for Sink {
            fn record(&self, r: &AuditRecord) {
                self.0.lock().unwrap().push(r.clone());
            }
        }
        let sink = Arc::new(Sink::default());
        let (host, a, b) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host).with_audit(sink.clone());
        let (t, c) = issuer.mint(req(&a)).unwrap();
        let proof = prove(&a, &t, "exchange", &c.call);
        let (t2, _) = issuer.exchange(&t, Some(&proof), "b", Some(b.kid().into()), None, "call-2", "far.y", &ProofCache::default()).unwrap();
        let records = sink.0.lock().unwrap().clone();
        assert_eq!(records.iter().map(|r| r.kind).collect::<Vec<_>>(), [AuditKind::Mint, AuditKind::Exchange]);
        assert_eq!(records[1].act.len(), 3);
        let text = serde_json::to_string(&records).unwrap();
        for secret in [&t, &t2, &proof] {
            for part in secret.split('.').filter(|p| p.len() > 8) {
                assert!(!text.contains(part), "an audit record holds a token's or a proof's bytes");
            }
        }
    }

    /// DYNAUTH-12's property: `scope ⊆ reach` for every mint — over every
    /// reach, forwarded grant and consent drawn from a small lattice.
    #[test]
    fn every_mint_s_scope_is_within_the_reach() {
        let scopes = ["*", "A", "B", "C"];
        let subsets = |n: usize| -> Vec<Vec<String>> {
            (0..(1usize << n)).map(|m| (0..n).filter(|i| m & (1 << i) != 0).map(|i| scopes[i].to_string()).collect()).collect()
        };
        let (host, peer) = (PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let mut minted = 0;
        for reach in subsets(scopes.len()) {
            for consent_a in subsets(scopes.len()) {
                for consent_b in subsets(3) {
                    for forwarded in [None, Some("far.m")] {
                        let needs = vec![("shop.items".to_string(), consent_a.clone()), ("dyn.{peer}".to_string(), consent_b.clone())];
                        let scope = mint_scope(forwarded, &reach, &needs);
                        let (_, c) = issuer.mint(MintRequest { scope, ..req(&peer) }).unwrap();
                        minted += 1;
                        for e in &c.scope {
                            let (g, s) = e.rsplit_once('@').unwrap();
                            assert!(reach.iter().any(|r| r == "*" || r == s), "{e} outside the reach {reach:?}");
                            if g != "far.m" {
                                let consent = needs.iter().find(|(n, _)| n == g).map(|(_, c)| c).unwrap();
                                assert!(consent.iter().any(|c| c == "*" || c == s), "{e} outside its consent {consent:?}");
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(minted, 16 * 16 * 8 * 2);
    }

    /// DYNAUTH-6: an onward token never holds more than the presented one —
    /// a need only where it held the same grant, the forwarded grant only
    /// where it held the grant the onward call was admitted on.
    #[test]
    fn an_onward_scope_never_widens() {
        let scopes = ["*", "A", "B"];
        let subsets = |n: usize| -> Vec<Vec<String>> {
            (0..(1usize << n)).map(|m| (0..n).filter(|i| m & (1 << i) != 0).map(|i| scopes[i].to_string()).collect()).collect()
        };
        let peer = PeerKey::generate();
        let issuer = TokenIssuer::new(PeerKey::generate());
        for held_slot in subsets(3) {
            for held_need in subsets(3) {
                let mut presented_scope: Vec<String> = held_slot.iter().map(|s| format!("dyn.{{peer}}@{s}")).collect();
                presented_scope.extend(held_need.iter().map(|s| format!("shop.items@{s}")));
                let (_, presented) = issuer.mint(MintRequest { scope: presented_scope.clone(), ..req(&peer) }).unwrap();
                for reach in subsets(3) {
                    for consent in subsets(3) {
                        let needs = vec![("shop.items".to_string(), consent.clone()), ("auth.grant".to_string(), vec!["*".to_string()])];
                        let got = onward_scope(&presented, Some("dyn.{peer}"), Some("far.forecast"), &reach, &needs);
                        for e in &got {
                            let (g, s) = e.rsplit_once('@').unwrap();
                            let host_grant = if g == "far.forecast" { "dyn.{peer}" } else { g };
                            assert!(presented.scopes_for(host_grant).iter().any(|h| h == "*" || h == s), "{e} wider than {presented_scope:?}");
                            assert!(reach.iter().any(|r| r == "*" || r == s), "{e} outside the reach {reach:?}");
                            assert_ne!(g, "auth.grant", "a need the presented token did not hold");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_key_file_is_made_private_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k/dyn.key");
        let a = PeerKey::load_or_create(&path).unwrap();
        let b = PeerKey::load_or_create(&path).unwrap();
        assert_eq!(a.kid(), b.kid());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(PeerKey::load_or_create(&path).is_err());
        }
        assert!(!format!("{a:?}").contains(&b64(&a.signing.to_bytes())));
    }
}
