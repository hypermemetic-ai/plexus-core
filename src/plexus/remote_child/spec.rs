//! What a child is (`ChildSpec`), how the service reaches it
//! (`ChildOptions`, `Backoff`) and how that fails (`ChildError`).

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// A child service: an activation in another process, mounted under `name`.
///
/// Spelled `NAME=stdio:CMD ARGS…` (the command split as a shell would split
/// it, then run without one) or `NAME=ws://HOST:PORT[/PATH]` (`wss://` with
/// the `child-wss` feature). `NAME` is one segment of `[A-Za-z0-9_-]` — the
/// mount name, which wins over the namespace the child declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildSpec {
    /// A process the service spawns; frames on its stdin / stdout (spec/11).
    Stdio { name: String, argv: Vec<String> },
    /// A service the service dials; frames on a WebSocket (spec/00, 01).
    Ws { name: String, url: String },
}

impl ChildSpec {
    /// The mount name.
    pub fn name(&self) -> &str {
        match self {
            Self::Stdio { name, .. } | Self::Ws { name, .. } => name,
        }
    }
}

impl fmt::Display for ChildSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdio { name, argv } => write!(f, "{name}=stdio:{}", shell_words::join(argv)),
            Self::Ws { name, url } => write!(f, "{name}={url}"),
        }
    }
}

fn spec_err(s: &str, why: impl fmt::Display) -> ChildError {
    ChildError::Spec(format!("`{s}`: {why}"))
}

impl FromStr for ChildSpec {
    type Err = ChildError;

    fn from_str(s: &str) -> Result<Self, ChildError> {
        let (name, rest) = s.split_once('=').ok_or_else(|| spec_err(s, "no `=`: a child is NAME=stdio:CMD or NAME=ws://HOST:PORT"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(spec_err(s, "an empty mount name"));
        }
        if name.contains('.') {
            return Err(spec_err(s, format!("the mount name `{name}` is dotted: it is one segment (a method's path is `{name}.<method>`)")));
        }
        if let Some(bad) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-')) {
            return Err(spec_err(s, format!("the mount name `{name}` holds `{bad}`: only letters, digits, `_` and `-`")));
        }
        let name = name.to_string();
        if let Some(cmd) = rest.strip_prefix("stdio:") {
            let mut argv = shell_words::split(cmd).map_err(|e| spec_err(s, format!("its command does not split: {e}")))?;
            // `NAME=stdio:"CMD ARGS"` with the quotes kept (an env var, a
            // config file): one quoted word is the whole command.
            if argv.len() == 1 && argv[0].contains(char::is_whitespace) {
                argv = shell_words::split(&argv[0]).map_err(|e| spec_err(s, format!("its command does not split: {e}")))?;
            }
            if argv.is_empty() {
                return Err(spec_err(s, "no command after `stdio:`"));
            }
            return Ok(Self::Stdio { name, argv });
        }
        if rest.starts_with("ws://") || rest.starts_with("wss://") {
            let host = rest.split_once("://").map(|(_, h)| h).unwrap_or("");
            let host = host.split(['/', '?', '#']).next().unwrap_or("");
            if host.is_empty() || host.starts_with(':') {
                return Err(spec_err(s, "a WebSocket child names its host: ws://HOST:PORT"));
            }
            return Ok(Self::Ws { name, url: rest.to_string() });
        }
        let scheme = rest.split_once(':').map(|(a, _)| a).unwrap_or(rest);
        Err(spec_err(s, format!("unknown scheme `{scheme}`: a child is reached by `stdio:CMD`, `ws://…` or `wss://…`")))
    }
}

/// KEEL-7: the reason a dial refused for its transport gives, as plexus-dyn's
/// `refused` says it.
pub const INSECURE_TRANSPORT: &str = "insecure_transport";

/// KEEL-7 (DYNAUTH-8, TM-3): whether the service may dial `url` — `wss://`
/// anywhere, `ws://` only to loopback ([`is_loopback_host`]) unless
/// `insecure_ws` (`transport.insecure_ws`) allows it. Every dial the
/// service makes asks it before a socket opens: a `ws://` child's, a
/// dial-out's, plexus-dyn's. `Err`: why, said (the reason is
/// [`INSECURE_TRANSPORT`]).
pub fn check_ws_url(url: &str, insecure_ws: bool) -> Result<(), String> {
    let rest = if let Some(r) = url.strip_prefix("wss://") {
        return match url_host(r) {
            Some(_) => Ok(()),
            None => Err(format!("`{url}` names no host")),
        };
    } else if let Some(r) = url.strip_prefix("ws://") {
        r
    } else {
        return Err(format!("`{url}`: a peer is reached by ws:// or wss://"));
    };
    let Some(host) = url_host(rest) else { return Err(format!("`{url}` names no host")) };
    if is_loopback_host(&host) || insecure_ws {
        return Ok(());
    }
    Err(format!(
        "`{url}`: plain ws:// only to loopback (127.0.0.0/8, ::1, localhost); a peer beyond it is reached by wss://, its hop (who calls, under what ceiling) never in clear (`transport.insecure_ws` allows it, a test network's)"
    ))
}

/// KEEL-7: whether `url` is plain `ws://` beyond loopback — a dial
/// [`check_ws_url`] admits only under `transport.insecure_ws`, and which
/// says so where its mount is listed.
pub fn is_insecure_ws(url: &str) -> bool {
    url.starts_with("ws://") && check_ws_url(url, false).is_err() && check_ws_url(url, true).is_ok()
}

/// The host of `authority[/path]`: no user info, no port, an IPv6
/// literal without its brackets, lower case.
fn url_host(rest: &str) -> Option<String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split_once(']')?.0
    } else {
        authority.split(':').next().unwrap_or("")
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// KEEL-7: loopback as every dial reads it — `127.0.0.0/8`, `::1`, an
/// IPv4-mapped `127.x`, and `localhost` (a trailing dot allowed); a name
/// that only begins so (`localhost.example.com`) is not.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_loopback(),
        Ok(std::net::IpAddr::V6(a)) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        Err(_) => false,
    }
}

/// How fast a child that died is started (or dialed) again: the n-th restart
/// within a minute waits `initial · 2ⁿ`, at most `max`, after the death; past
/// `per_minute` restarts in the last minute a call is answered
/// `child_unavailable` at once until the minute has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    pub per_minute: usize,
}

impl Default for Backoff {
    /// 0.5 s → 30 s, at most 5 restarts a minute.
    fn default() -> Self {
        Self { initial: Duration::from_millis(500), max: Duration::from_secs(30), per_minute: 5 }
    }
}

impl Backoff {
    /// The wait before restart number `n + 1` of the current minute.
    pub fn delay(&self, n: usize) -> Duration {
        let factor = 1u32.checked_shl(n.min(31) as u32).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }
}

/// How the service reaches its children.
#[derive(Debug, Clone)]
pub struct ChildOptions {
    /// The hop's `principal` (spec/12) on stdio, where no upgrade proves one:
    /// the service naming itself, `service:<its namespace>`. Over a
    /// WebSocket with a [`key`](Self::key) the principal is that key's.
    pub principal: String,
    /// A key file (synapse's `~/.plexus/keys/<name>.key`: a 32-byte Ed25519
    /// seed, base64, mode 0600): a WebSocket child is dialed with its proof
    /// (spec/00). Read at each dial and never kept, logged or passed on.
    pub key: Option<PathBuf>,
    /// The proof's agent id (spec/00): 1–64 of `[A-Za-z0-9._-]`.
    pub agent: String,
    /// A child's answer to `_info`, its schema, and every call's open.
    pub timeout: Duration,
    /// Calls open on one child at once; past it, `too_many_calls`.
    pub max_calls: usize,
    /// Items held for one call whose caller has not read them; past it the
    /// child's reader waits (lossless; the child's other calls wait too).
    pub buffer: usize,
    /// Variables passed from the service's environment to a stdio child,
    /// beyond `PATH`, `HOME`, `LANG` and `PLEXUS_CHILD_NAME`.
    pub env: Vec<String>,
    /// Restarting (or redialing) a child that died.
    pub backoff: Backoff,
    /// NEST-4: how many levels of static children a mount walks
    /// (`--child-max-depth`); a deeper one fails the mount, naming it.
    pub max_depth: usize,
    /// NEST-6: how many dynamic instances' schemas a mount keeps
    /// (`--child-schema-cache`), the least recently used out first; 0
    /// keeps none.
    pub schema_cache: usize,
    /// NEST-11: the service the child is mounted in, whose routing and gate
    /// take the calls the child makes back (`_host.call`). `None`: the
    /// service a call was routed in when the child was connected (inside a
    /// call), else the service of the first call forwarded to it.
    pub host: Option<crate::plexus::service_scope::WeakService>,
    /// NEST-12: a WebSocket child is pinged this often, and marked down —
    /// every open call `child_unavailable`, the next one redialing — when
    /// nothing has come from it for twice as long. `None`: never pinged.
    pub ping: Option<Duration>,
    /// NEST-16: a child whose schema declares no `needs` may call up, under
    /// a call it serves, anything that call's caller could (NEST-11's rule,
    /// `--child-legacy-upcalls`). Off: such a child has the standard upward
    /// interface alone (`host.schema`, `host.whoami`, `host.log`,
    /// `host.notify`). Kept for one release, for dendrites built before
    /// `needs`; a child that declares needs is held to them either way.
    pub legacy_upcalls: bool,
    /// DYNAUTH-8: a PEM file of certificate authorities a `wss://` child's
    /// certificate may chain to, beside the webpki roots (a private CA, a
    /// test network's). Certificates are always validated; nothing turns
    /// that off.
    pub tls_roots: Option<PathBuf>,
    /// KEEL-7: dial plain `ws://` beyond loopback (`transport.insecure_ws`,
    /// a test network's). Off: such a child is refused before a socket
    /// opens ([`check_ws_url`]); on: dialed, and its mount says
    /// [`insecure`](crate::plexus::RemoteChild::insecure).
    pub insecure_ws: bool,
    /// DYNAUTH-12: the service's peer-token issuer. With one, every call
    /// forwarded for a signed-in caller carries a token minted for it
    /// (`hop.token`): `aud` the child's proved key (bound to it), or
    /// `pipe:<name>` for a child on the service's own pipe; scope the
    /// forwarded grant and the child's needs (consented), within the call's
    /// reach. A WebSocket child that proved no key gets none. A keyed child
    /// calling back presents a proof of possession with each call.
    pub tokens: Option<std::sync::Arc<crate::plexus::peer_token::TokenIssuer>>,
    /// KEEL-32: paths of the service whose schemas the child may read
    /// outside any call before its needs are known — what it is grown
    /// against at its start (plexus-dyn: a dendrite's `--via-host`
    /// targets, `dyn.peer.<target>`). A path at, above or below one of these
    /// is answered; any other only as the child's consented needs allow.
    pub schemas: Vec<String>,
}

impl Default for ChildOptions {
    fn default() -> Self {
        Self {
            principal: "service:service".into(),
            key: None,
            agent: "service".into(),
            timeout: Duration::from_secs(5),
            max_calls: 1024,
            buffer: 1024,
            env: Vec::new(),
            backoff: Backoff::default(),
            max_depth: 8,
            schema_cache: 1024,
            host: None,
            ping: None,
            legacy_upcalls: false,
            tls_roots: None,
            insecure_ws: false,
            tokens: None,
            schemas: Vec::new(),
        }
    }
}

impl ChildOptions {
    /// The defaults for the service named `service`: its hop principal
    /// `service:<service>`, its proof's agent id `service`.
    pub fn for_service(service: &str) -> Self {
        Self { principal: format!("service:{service}"), agent: service.to_string(), ..Self::default() }
    }

    /// NEST-11: these options, the child mounted in `service` (see
    /// [`ChildOptions::host`]).
    /// NEST-16: NEST-11's broad rule for a child that declares no `needs`
    /// ([`ChildOptions::legacy_upcalls`]).
    pub fn with_legacy_upcalls(mut self, on: bool) -> Self {
        self.legacy_upcalls = on;
        self
    }

    /// KEEL-32: the paths whose schemas the child may read outside any
    /// call before its needs are known ([`ChildOptions::schemas`]).
    pub fn with_schemas<I: IntoIterator<Item = S>, S: Into<String>>(mut self, paths: I) -> Self {
        self.schemas = paths.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_host(mut self, service: &crate::plexus::DynamicHub) -> Self {
        self.host = Some(service.downgrade());
        self
    }
}

/// Why a child was not mounted.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ChildError {
    /// A `--child` value that does not read.
    #[error("child spec {0}")]
    Spec(String),
    /// The child did not start, did not answer, or answered a schema the
    /// service will not mount: `(mount name, why)`.
    #[error("child {0}: {1}")]
    Start(String, String),
}

/// `5s`, `500ms`, `2m`, `1.5` (seconds) — `--child-timeout`'s spelling.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = match s.find(|c: char| !(c.is_ascii_digit() || c == '.')) {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s, "s"),
    };
    let n: f64 = num.parse().map_err(|_| format!("`{s}` is not a duration (5s, 500ms, 2m)"))?;
    let secs = match unit {
        "ms" => n / 1e3,
        "s" | "" => n,
        "m" => n * 60.0,
        _ => return Err(format!("`{s}`: the unit is ms, s or m")),
    };
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("`{s}` is not a positive duration"));
    }
    Ok(Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_spec_parses() {
        let s: ChildSpec = r#"echo=stdio:python -I -m echo --x "a b""#.parse().unwrap();
        assert_eq!(s, ChildSpec::Stdio { name: "echo".into(), argv: vec!["python".into(), "-I".into(), "-m".into(), "echo".into(), "--x".into(), "a b".into()] });
        let s: ChildSpec = r#"echo=stdio:"python3 -I stub.py --stdio""#.parse().unwrap();
        assert_eq!(s, ChildSpec::Stdio { name: "echo".into(), argv: vec!["python3".into(), "-I".into(), "stub.py".into(), "--stdio".into()] });
        assert_eq!("echo=ws://h:1".parse::<ChildSpec>().unwrap(), ChildSpec::Ws { name: "echo".into(), url: "ws://h:1".into() });
        assert_eq!("e-2=wss://h/ws".parse::<ChildSpec>().unwrap(), ChildSpec::Ws { name: "e-2".into(), url: "wss://h/ws".into() });
        let refused = |s: &str, why: &str| {
            let e = s.parse::<ChildSpec>().unwrap_err().to_string();
            assert!(e.contains(why), "{s}: {e}");
        };
        refused("echo", "no `=`");
        refused("=stdio:x", "empty mount name");
        refused("a.b=stdio:x", "dotted");
        refused("a b=stdio:x", "holds ` `");
        refused("echo=tcp://h:1", "unknown scheme `tcp`");
        refused("echo=stdio:", "no command");
        refused(r#"echo=stdio:python "unclosed"#, "does not split");
        refused("echo=ws://:1", "names its host");
    }

    #[test]
    fn child_spec_round_trips() {
        for s in [r#"echo=stdio:python -I "a b""#, "echo=ws://127.0.0.1:4480"] {
            let spec: ChildSpec = s.parse().unwrap();
            assert_eq!(spec.to_string().parse::<ChildSpec>().unwrap(), spec);
        }
    }

    #[test]
    fn backoff_doubles_to_its_cap() {
        let b = Backoff::default();
        let ms: Vec<u128> = (0..8).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(ms, [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]);
    }

    #[test]
    fn durations_read() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("0s").is_err() && parse_duration("x").is_err() && parse_duration("3h").is_err());
    }
}
