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
