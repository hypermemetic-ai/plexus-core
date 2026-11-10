//! NEST-25 · first contact, the way ssh does it: the node learns the host's
//! key once and pins it (its known-hosts file), and both ends show one short
//! **pairing code** a person compares instead of 64 hex characters.
//!
//! The code (plexus-wire spec/14's first contact): the node sends
//! `_info {nonce, commit}` — `commit` the [`commitment`] to a nonce of its
//! own it keeps back — the host answers with a fresh `host_nonce` beside its
//! key proof, and the node reveals its nonce in the offer (`pairing_nonce`),
//! which the host checks against the commitment. Both ends then hold the same
//! two keys and the same two nonces, and [`pairing_code`] is the first 8
//! RFC 4648 base32 characters of their domain-separated SHA-256, `MMG4-2KLG`
//! (menger's pairing-code form, TETHER-12).
//!
//! What it protects against: a man in the middle at first contact who
//! answers each end with a key of its own. The two codes then differ, and
//! because the node committed to its nonce before it saw the host's, the
//! middle cannot search for keys whose codes agree: one try in 2⁴⁰ matches,
//! and every try is an offer an operator sees. What it does not: an operator
//! who accepts without comparing the code.

use std::path::{Path, PathBuf};

use base64::Engine;
use sha2::{Digest, Sha256};

/// The domain the pairing code's hash is taken in.
pub const PAIRING_CONTEXT: &str = "plexus-dial-pairing/v1";

/// How many base32 characters a pairing code has (40 bits).
pub const CODE_CHARS: usize = 8;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn sha(parts: &[&str]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        // Each part length-prefixed: no two lists of parts hash alike.
        h.update((p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
    }
    h.finalize().into()
}

/// The node's commitment to `nonce` (sent at `_info`, before it sees the
/// host's nonce): base64url of its domain-separated SHA-256.
pub fn commitment(nonce: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha(&[PAIRING_CONTEXT, "commit", nonce]))
}

/// Whether `nonce` is the one `commit` committed to.
pub fn commits_to(commit: &str, nonce: &str) -> bool {
    commitment(nonce) == commit
}

/// The pairing code of one connection: both keys (`key:<hex>`) and both
/// nonces, `XXXX-XXXX`.
pub fn pairing_code(host_key: &str, node_key: &str, node_nonce: &str, host_nonce: &str) -> String {
    let d = sha(&[PAIRING_CONTEXT, "code", host_key, node_key, node_nonce, host_nonce]);
    let bits = d[..5].iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let chars: String = (0..CODE_CHARS).map(|i| ALPHABET[((bits >> (35 - 5 * i)) & 31) as usize] as char).collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// A code as typed — any case, dashes and spaces optional — as
/// [`pairing_code`] writes it, or `None` when it is not one.
pub fn normalize_code(typed: &str) -> Option<String> {
    let chars: String = typed.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect();
    let ok = chars.len() == CODE_CHARS && chars.bytes().all(|b| ALPHABET.contains(&b));
    ok.then(|| format!("{}-{}", &chars[..4], &chars[4..]))
}

/// A key's fingerprint as ssh shows one: `SHA256:<base64>` of its 32 bytes.
pub fn key_fingerprint(principal: &str) -> Option<String> {
    let key = crate::plexus::peer_token::key_of(principal)?;
    Some(format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(key.as_bytes()))))
}

/// The node's known hosts: each host it said yes to, by URL, and the key
/// pinned for it — a line `<url> key:<hex>`. Read as a key file is (not
/// through a link, the user's own, 0600); written whole, 0600.
#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
}

/// A URL as the known-hosts file keys it (no trailing `/`).
fn host_of(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

impl KnownHosts {
    /// The file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `$XDG_CONFIG_HOME/plexus/known_hosts`, else `~/.config/plexus/known_hosts`.
    pub fn default_path() -> Option<PathBuf> {
        let from = |k: &str| std::env::var_os(k).map(PathBuf::from).filter(|p| p.is_absolute());
        from("XDG_CONFIG_HOME").or_else(|| from("HOME").map(|h| h.join(".config"))).map(|c| c.join("plexus").join("known_hosts"))
    }

    /// Where it is kept.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn entries(&self) -> Result<Vec<(String, String)>, String> {
        let Some(bytes) = crate::plexus::peer_token::read_private_if_any(&self.path)? else { return Ok(Vec::new()) };
        let text = String::from_utf8(bytes).map_err(|_| format!("{} is not text", self.path.display()))?;
        let mut out = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_whitespace().collect::<Vec<_>>().as_slice() {
                [url, key] if crate::plexus::peer_token::key_of(key).is_some() => out.push((host_of(url).to_string(), key.to_string())),
                _ => return Err(format!("{}:{}: not `<url> key:<64 hex>`", self.path.display(), n + 1)),
            }
        }
        Ok(out)
    }

    /// The key pinned for `url`, if one is.
    pub fn get(&self, url: &str) -> Result<Option<String>, String> {
        Ok(self.entries()?.into_iter().find(|(u, _)| u == host_of(url)).map(|(_, k)| k))
    }

    /// Pin `key` for `url`. Refused when another key is pinned for it: a
    /// host whose key changed is never re-pinned here, only by a person
    /// editing the file.
    pub fn add(&self, url: &str, key: &str) -> Result<(), String> {
        if crate::plexus::peer_token::key_of(key).is_none() {
            return Err(format!("`{key}` is not a key (`key:<64 hex>`)"));
        }
        let mut entries = self.entries()?;
        match entries.iter().find(|(u, _)| u == host_of(url)) {
            Some((_, k)) if k == key => return Ok(()),
            Some((_, k)) => return Err(format!("{} pins another key for {url} ({k}): remove that line by hand to trust a new one", self.path.display())),
            None => entries.push((host_of(url).to_string(), key.to_string())),
        }
        if let Some(dir) = self.path.parent() {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                }
            }
        }
        let text: String = entries.iter().map(|(u, k)| format!("{u} {k}\n")).collect();
        let tmp = self.path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        crate::plexus::peer_token::write_private(&tmp, text.as_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn the_code_is_eight_base32_characters_and_moves_with_every_input() {
        let c = pairing_code(A, B, "n1", "n2");
        assert_eq!(c.len(), 9);
        assert_eq!(normalize_code(&c.to_lowercase().replace('-', " ")), Some(c.clone()));
        for other in [pairing_code(B, A, "n1", "n2"), pairing_code(A, B, "n2", "n1"), pairing_code(A, B, "n1", "n3")] {
            assert_ne!(c, other);
        }
    }

    #[test]
    fn a_commitment_binds_its_nonce() {
        assert!(commits_to(&commitment("x"), "x"));
        assert!(!commits_to(&commitment("x"), "y"));
    }

    #[test]
    fn known_hosts_pins_once_and_never_repins() {
        let dir = tempfile::tempdir().unwrap();
        let k = KnownHosts::new(dir.path().join("plexus/known_hosts"));
        assert_eq!(k.get("ws://h/ws").unwrap(), None);
        k.add("ws://h/ws/", A).unwrap();
        assert_eq!(k.get("ws://h/ws").unwrap().as_deref(), Some(A));
        assert!(k.add("ws://h/ws", B).unwrap_err().contains("another key"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(k.path()).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
