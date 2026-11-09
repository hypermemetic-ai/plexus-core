//! NEST-21 · a service's configuration at runtime, in three layers.
//!
//! 1. **Settings.** A subsystem declares each knob once, as a typed
//!    constant:
//!
//!    ```
//!    use plexus_core::plexus::config::Setting;
//!    pub const INSECURE_WS: Setting<bool> = plexus_core::setting!(
//!        "transport.insecure_ws", default = false,
//!        reload = Live, sensitivity = Public, scope = Service, critical = true,
//!        doc = "plain ws:// to a host beyond loopback");
//!    ```
//!
//!    Its schema is its type's `JsonSchema`. `reload` is [`Reload::Live`]
//!    (applies at once, watchers told) or [`Reload::Restart`] (a runtime set
//!    is stored and shown as `pending` until the service starts again).
//!    [`Sensitivity::Secret`] is write-only: read back as set or unset and a
//!    hash, never the value. `remote = false`: readable over the wire,
//!    settable only from the host's code or its file. `critical = true`:
//!    over the wire only by an admin (the grant `config.critical`) and only
//!    as a confirmed commit — the seam SIGN-1's signed calls fill
//!    (`signed(hardware, uv)`).
//! 2. **The library.** [`Config`] is a capability handle, not a global: a
//!    service holds one ([`DynamicHub::config`](super::DynamicHub::config))
//!    and hands it to what it builds. [`Config::get`], [`Config::set`],
//!    [`Config::reset`], [`Config::watch`], [`Config::list`],
//!    [`Config::schema`]. Sources, lowest first: the default < the file <
//!    a flag or the environment < a set at runtime ([`Source`]). A runtime
//!    set is kept across a restart only when the host gives the store a file
//!    ([`Config::with_file`]); at the next start the file's values are the
//!    file layer, under the flags. Every set, reset, confirm and revert is
//!    an audit record ([`ConfigRecord`]: who — the actor chain — when, the
//!    key, the old and new value's hashes, never a value) on the
//!    `plexus::audit` target DYNAUTH-7's records use, and to every
//!    [`ConfigAudit`] sink.
//! 3. **The `config` activation** ([`ConfigActivation`]): each key a dynamic
//!    child — `config.{key}.get | set | reset | confirm`, `config.list`,
//!    `config.watch` — granted per key through NEST-5's slot grants, and
//!    admin's alone unless a role lists one. `set --confirm-within 60s`
//!    applies at once and reverts unless `config.{key}.confirm` comes in
//!    time.

mod activation;
pub mod settings;

pub use activation::{ConfigActivation, SettingEvent, ConfigKeyActivation, ConfigRefusal, CRITICAL_GRANT};

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// When a change to a setting takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reload {
    /// At once: [`Config::get`] answers it and watchers are told.
    Live,
    /// At the next start: a runtime set is stored and shown as `pending`;
    /// [`Config::get`] answers what the service started with.
    Restart,
}

/// Whether a setting's value may be read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Read back as it is.
    Public,
    /// Write-only: read back as set or unset and a hash (salted per process,
    /// so it tells a change, never the value).
    Secret,
}

/// What a setting governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// This service.
    Service,
    /// The whole process (the log's redactor): the last service to set it wins.
    Process,
}

/// Where a setting's value comes from, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The setting's own default.
    Default,
    /// The store's file, as read at start.
    File,
    /// A flag or the environment, given at start by the host.
    Flag,
    /// A set at runtime (the library or the `config` activation).
    Runtime,
}

/// A value a setting may hold.
pub trait SettingValue: Serialize + DeserializeOwned + JsonSchema + Clone + Send + Sync + 'static {}
impl<T: Serialize + DeserializeOwned + JsonSchema + Clone + Send + Sync + 'static> SettingValue for T {}

/// A setting, declared once by the subsystem it governs — usually through
/// [`setting!`](crate::setting).
pub struct Setting<T> {
    /// Dotted, each segment `[a-z][a-z0-9_]*`: `transport.insecure_ws`.
    pub key: &'static str,
    /// What it governs, in a line.
    pub doc: &'static str,
    pub default: fn() -> T,
    pub reload: Reload,
    pub sensitivity: Sensitivity,
    pub scope: Scope,
    /// Settable over the wire (the `config` activation); `false`: only from
    /// the host's code or the file.
    pub remote: bool,
    /// Over the wire, admin only and only as a confirmed commit (SIGN-1:
    /// later `signed(hardware, uv)`).
    pub critical: bool,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for Setting<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Setting<T> {}

impl<T> std::fmt::Debug for Setting<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Setting({})", self.key)
    }
}

impl<T> Setting<T> {
    /// `key` with `default`: live, public, the service's, settable over the
    /// wire, not critical.
    pub const fn new(key: &'static str, default: fn() -> T) -> Self {
        Self { key, doc: "", default, reload: Reload::Live, sensitivity: Sensitivity::Public, scope: Scope::Service, remote: true, critical: false, _t: PhantomData }
    }
    pub const fn reload(mut self, r: Reload) -> Self {
        self.reload = r;
        self
    }
    pub const fn sensitivity(mut self, s: Sensitivity) -> Self {
        self.sensitivity = s;
        self
    }
    pub const fn scope(mut self, s: Scope) -> Self {
        self.scope = s;
        self
    }
    pub const fn remote(mut self, r: bool) -> Self {
        self.remote = r;
        self
    }
    pub const fn critical(mut self, c: bool) -> Self {
        self.critical = c;
        self
    }
    pub const fn doc(mut self, d: &'static str) -> Self {
        self.doc = d;
        self
    }
}

/// Declare a [`Setting`]: `setting!("key", default = EXPR, reload = Live,
/// sensitivity = Public, scope = Service, remote = false, critical = true,
/// doc = "…")` — everything after `default` optional, in any order.
#[macro_export]
macro_rules! setting {
    ($key:literal, default = $d:expr $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($crate::plexus::config::Setting::new($key, || $d)) $($($rest)*)?)
    };
    (@opt ($s:expr)) => { $s };
    (@opt ($s:expr) reload = $v:ident $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($s.reload($crate::plexus::config::Reload::$v)) $($($rest)*)?)
    };
    (@opt ($s:expr) sensitivity = $v:ident $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($s.sensitivity($crate::plexus::config::Sensitivity::$v)) $($($rest)*)?)
    };
    (@opt ($s:expr) scope = $v:ident $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($s.scope($crate::plexus::config::Scope::$v)) $($($rest)*)?)
    };
    (@opt ($s:expr) remote = $v:literal $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($s.remote($v)) $($($rest)*)?)
    };
    (@opt ($s:expr) critical = $v:literal $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($s.critical($v)) $($($rest)*)?)
    };
    (@opt ($s:expr) doc = $v:literal $(, $($rest:tt)*)?) => {
        $crate::setting!(@opt ($s.doc($v)) $($($rest)*)?)
    };
}

/// A duration as a setting holds it: `"5s"`, `"500ms"`, `"2m"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Millis(pub Duration);

impl Millis {
    pub const fn ms(n: u64) -> Self {
        Self(Duration::from_millis(n))
    }
    pub const fn secs(n: u64) -> Self {
        Self(Duration::from_secs(n))
    }
}

impl Serialize for Millis {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let ms = self.0.as_millis();
        if ms % 1000 == 0 {
            s.serialize_str(&format!("{}s", ms / 1000))
        } else {
            s.serialize_str(&format!("{ms}ms"))
        }
    }
}

impl<'de> Deserialize<'de> for Millis {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Text(String),
            Ms(u64),
        }
        match Either::deserialize(d)? {
            Either::Text(t) => parse_duration(&t).map(Millis).map_err(serde::de::Error::custom),
            Either::Ms(n) => Ok(Millis::ms(n)),
        }
    }
}

impl JsonSchema for Millis {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Duration".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[0-9]+(\\.[0-9]+)?(ms|s|m)$",
            "description": "a duration: 500ms, 5s, 2m"
        })
    }
}

/// `5s`, `500ms`, `2m` (a bare number is seconds).
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

/// The segments a key may not use: the key nodes' own methods.
pub const RESERVED_SEGMENTS: &[&str] = &["get", "set", "reset", "confirm", "names", "list", "watch", "schema"];

/// Whether `key` is a setting's key: dotted segments of `[a-z][a-z0-9_]*`,
/// none of [`RESERVED_SEGMENTS`].
pub fn check_key(key: &str) -> Result<(), String> {
    let ok_seg = |s: &str| {
        let mut b = s.bytes();
        matches!(b.next(), Some(c) if c.is_ascii_lowercase()) && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    };
    if key.is_empty() || !key.split('.').all(ok_seg) {
        return Err(format!("`{key}` is not a setting's key: dotted segments of [a-z][a-z0-9_]*"));
    }
    if let Some(r) = key.split('.').find(|s| RESERVED_SEGMENTS.contains(s)) {
        return Err(format!("`{key}`: `{r}` is a key node's method, not a segment"));
    }
    Ok(())
}

/// Who did it: the principal, then each service it came through, nearest
/// first — or `["host"]` for the host's own code.
pub type Actor = Vec<String>;

/// The actor of the running call: its caller as the gate admitted them (or
/// the hop's chain, in a child), else the host.
pub fn current_actor() -> Actor {
    if let Ok(c) = crate::call::caller() {
        let mut out = vec![c.auth().and_then(|a| a.principal()).map(|p| p.to_string()).unwrap_or_else(|| "anonymous".into())];
        if let Some(h) = c.context().hop() {
            out.push(h.principal.clone());
        }
        return out;
    }
    if let Ok(h) = crate::call::hop() {
        let mut out: Vec<String> = h.for_.iter().rev().cloned().collect();
        out.push(h.principal.clone());
        return out;
    }
    vec!["host".into()]
}

/// What an audit record is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigAction {
    Set,
    Reset,
    Confirmed,
    Reverted,
    /// A set refused (over the wire: `remote = false`, critical without a
    /// confirm, not admin).
    Refused,
}

/// NEST-21: one audit record — never a value, only hashes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigRecord {
    pub action: ConfigAction,
    pub key: String,
    /// Who: the principal, then each service it came through.
    pub actor: Actor,
    /// Unix milliseconds.
    pub at: i64,
    /// The value in effect before, hashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_hash: Option<String>,
    /// The value set, hashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<String>,
    /// A confirmed commit's deadline (unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_until: Option<i64>,
    /// Why, for a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// NEST-21: where a configuration audit record goes besides `tracing`
/// (`plexus::audit`, beside DYNAUTH-7's token records) — PRIVACY-1's sink,
/// when there is one.
pub trait ConfigAudit: Send + Sync {
    fn record(&self, r: &ConfigRecord);
}

/// Why a set was refused by the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// No setting has this key (a prefix of some: `keys` lists them).
    Unknown { key: String, keys: Vec<String> },
    /// The value does not fit the setting's type.
    Invalid { key: String, message: String },
    /// Nothing to confirm on this key.
    NothingToConfirm { key: String },
    /// The store's file could not be written.
    Store { message: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { key, keys } if keys.is_empty() => write!(f, "no setting `{key}`"),
            Self::Unknown { key, keys } => write!(f, "`{key}` is not a setting; under it: {}", keys.join(", ")),
            Self::Invalid { key, message } => write!(f, "`{key}`: {message}"),
            Self::NothingToConfirm { key } => write!(f, "`{key}` has no change waiting to be confirmed"),
            Self::Store { message } => write!(f, "the store: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// What a set replaced.
#[derive(Debug, Clone, PartialEq)]
pub struct Previous<T> {
    /// The value in effect before.
    pub value: T,
    pub source: Source,
}

/// A setting as it stands, as `config.list` and `config.{key}.get` show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KeyInfo {
    pub key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub doc: String,
    /// The value in effect (`None` for a secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// The value in effect, hashed (a secret's salted).
    pub hash: String,
    /// Set by anything above the default.
    pub set: bool,
    pub source: Source,
    /// The default (`None` for a secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    pub reload: Reload,
    pub sensitivity: Sensitivity,
    pub scope: Scope,
    pub remote: bool,
    pub critical: bool,
    /// A `Restart` setting's runtime value, waiting for the next start
    /// (`Some(null)` for a secret: one is waiting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Value>,
    /// A confirmed commit waiting: reverted at this time (unix ms) unless
    /// confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_until: Option<i64>,
    /// Its type's JSON Schema.
    pub schema: Value,
}

/// A change, as `config.watch` and [`Config::changes`] say it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigChange {
    pub action: ConfigAction,
    pub key: String,
    /// The value in effect now (`None` for a secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    pub hash: String,
    pub source: Source,
    pub actor: Actor,
    pub at: i64,
    /// A `Restart` setting: stored, not in effect until the next start.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_until: Option<i64>,
}

type Check = Arc<dyn Fn(Value) -> Result<Value, String> + Send + Sync>;
type Hook = Arc<dyn Fn(&Value) + Send + Sync>;

struct Pending {
    generation: u64,
    until: i64,
    /// The runtime layer before the first unconfirmed set.
    revert_to: Option<Value>,
}

struct Entry {
    doc: &'static str,
    reload: Reload,
    sensitivity: Sensitivity,
    scope: Scope,
    remote: bool,
    critical: bool,
    schema: Value,
    default: Value,
    check: Check,
    file: Option<Value>,
    flag: Option<Value>,
    runtime: Option<Value>,
    /// What `get` answers: the effective value (a `Restart` setting's: as
    /// it was without its runtime layer).
    applied: Value,
    applied_source: Source,
    tx: tokio::sync::watch::Sender<Value>,
    hooks: Vec<Hook>,
    confirm: Option<Pending>,
}

impl Entry {
    fn effective(&self) -> (Value, Source) {
        if let Some(v) = &self.runtime {
            return (v.clone(), Source::Runtime);
        }
        self.below_runtime()
    }

    fn below_runtime(&self) -> (Value, Source) {
        if let Some(v) = &self.flag {
            (v.clone(), Source::Flag)
        } else if let Some(v) = &self.file {
            (v.clone(), Source::File)
        } else {
            (self.default.clone(), Source::Default)
        }
    }

    /// Recompute what is applied; whether it moved.
    fn reapply(&mut self) -> bool {
        let (v, src) = match self.reload {
            Reload::Live => self.effective(),
            Reload::Restart if self.applied_source == Source::Runtime => return false,
            Reload::Restart => self.below_runtime(),
        };
        let moved = v != self.applied;
        self.applied = v;
        self.applied_source = src;
        moved
    }

    fn pending(&self) -> Option<Value> {
        match (self.reload, &self.runtime) {
            (Reload::Restart, Some(v)) if *v != self.applied => Some(v.clone()),
            _ => None,
        }
    }
}

struct Inner {
    entries: Mutex<BTreeMap<String, Entry>>,
    /// The store's file, and what it holds (keys not declared yet too).
    file: Option<PathBuf>,
    stored: Mutex<BTreeMap<String, Value>>,
    changes: tokio::sync::broadcast::Sender<ConfigChange>,
    audit: Mutex<Vec<Arc<dyn ConfigAudit>>>,
    salt: [u8; 16],
    generation: std::sync::atomic::AtomicU64,
}

/// NEST-21: a service's configuration — a capability handle, cheap to
/// clone; every clone is the same store.
#[derive(Clone)]
pub struct Config {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self.inner.entries.lock().unwrap().keys().cloned().collect();
        f.debug_struct("Config").field("file", &self.inner.file).field("keys", &keys).finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Config {
    /// A store kept in memory, with plexus-core's own settings declared
    /// ([`settings::declare_core`]).
    pub fn new() -> Self {
        Self::build(None, BTreeMap::new())
    }

    /// A store kept in `file` (JSON, `{ "key": value }`, 0600): read now —
    /// its values the file layer of each key, as it is declared — and
    /// written at every runtime set and reset. A missing file is an empty
    /// one.
    pub fn with_file(file: impl AsRef<Path>) -> Result<Self, String> {
        let file = file.as_ref().to_path_buf();
        let stored = match std::fs::read_to_string(&file) {
            Ok(text) => serde_json::from_str::<BTreeMap<String, Value>>(&text).map_err(|e| format!("{}: {e}", file.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(format!("{}: {e}", file.display())),
        };
        Ok(Self::build(Some(file), stored))
    }

    fn build(file: Option<PathBuf>, stored: BTreeMap<String, Value>) -> Self {
        let mut salt = [0u8; 16];
        let _ = getrandom_02::getrandom(&mut salt);
        let c = Self {
            inner: Arc::new(Inner {
                entries: Mutex::default(),
                file,
                stored: Mutex::new(stored),
                changes: tokio::sync::broadcast::Sender::new(256),
                audit: Mutex::default(),
                salt,
                generation: Default::default(),
            }),
        };
        settings::declare_core(&c);
        c
    }

    /// Also record to `sink`.
    pub fn with_audit(self, sink: Arc<dyn ConfigAudit>) -> Self {
        self.add_audit(sink);
        self
    }

    /// Also record to `sink` (on a shared handle).
    pub fn add_audit(&self, sink: Arc<dyn ConfigAudit>) {
        self.inner.audit.lock().unwrap().push(sink);
    }

    /// The store's file, if it has one.
    pub fn file(&self) -> Option<&Path> {
        self.inner.file.as_deref()
    }

    /// Whether two handles are the same store.
    pub fn same(&self, other: &Config) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn downgrade(&self) -> Weak<Inner> {
        Arc::downgrade(&self.inner)
    }

    /// Declare `s` here (once; again is nothing). A key declared with
    /// another type, or not a key, is refused, said loudly, and the first
    /// declaration kept.
    pub fn declare<T: SettingValue>(&self, s: &Setting<T>) {
        if let Err(why) = self.try_declare(s) {
            tracing::error!(target: "plexus::config", "{why}");
        }
    }

    /// [`Config::declare`], saying why not.
    pub fn try_declare<T: SettingValue>(&self, s: &Setting<T>) -> Result<(), String> {
        check_key(s.key)?;
        let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap_or(Value::Null);
        let mut entries = self.inner.entries.lock().unwrap();
        if let Some(e) = entries.get(s.key) {
            return if e.schema == schema { Ok(()) } else { Err(format!("`{}` is declared already with another type", s.key)) };
        }
        if let Some(clash) = entries.keys().find(|k| k.starts_with(&format!("{}.", s.key)) || s.key.starts_with(&format!("{k}."))) {
            return Err(format!("`{}` and `{clash}`: a key is never another's prefix", s.key));
        }
        let default = serde_json::to_value((s.default)()).map_err(|e| format!("`{}`'s default: {e}", s.key))?;
        let check: Check = Arc::new(|v: Value| {
            let t: T = match serde_json::from_value::<T>(v.clone()) {
                Ok(t) => t,
                // A CLI sends `--value true` as the string "true": read a
                // string that does not fit as JSON.
                Err(first) => match v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()).and_then(|j| serde_json::from_value::<T>(j).ok()) {
                    Some(t) => t,
                    None => return Err(first.to_string()),
                },
            };
            serde_json::to_value(t).map_err(|e| e.to_string())
        });
        let file = self.inner.stored.lock().unwrap().get(s.key).cloned().and_then(|v| match check(v) {
            Ok(v) => Some(v),
            Err(why) => {
                tracing::error!(target: "plexus::config", key = s.key, "the file's value does not fit, ignored: {why}");
                None
            }
        });
        let mut e = Entry {
            doc: s.doc,
            reload: s.reload,
            sensitivity: s.sensitivity,
            scope: s.scope,
            remote: s.remote,
            critical: s.critical,
            schema,
            default: default.clone(),
            check,
            file,
            flag: None,
            runtime: None,
            applied: default.clone(),
            applied_source: Source::Default,
            tx: tokio::sync::watch::Sender::new(default),
            hooks: Vec::new(),
            confirm: None,
        };
        e.reapply();
        e.tx.send_replace(e.applied.clone());
        entries.insert(s.key.to_string(), e);
        Ok(())
    }

    /// What `s` is now (its default if its stored value no longer fits).
    pub fn get<T: SettingValue>(&self, s: &Setting<T>) -> T {
        self.declare(s);
        let v = self.inner.entries.lock().unwrap().get(s.key).map(|e| e.applied.clone());
        v.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_else(s.default)
    }

    /// Where `s`'s value in effect comes from.
    pub fn source<T: SettingValue>(&self, s: &Setting<T>) -> Source {
        self.declare(s);
        self.inner.entries.lock().unwrap().get(s.key).map(|e| e.applied_source).unwrap_or(Source::Default)
    }

    /// Set `s` at runtime, as the running call's caller (or the host).
    pub fn set<T: SettingValue>(&self, s: &Setting<T>, value: T) -> Result<Previous<T>, ConfigError> {
        self.declare(s);
        let v = serde_json::to_value(value).map_err(|e| ConfigError::Invalid { key: s.key.into(), message: e.to_string() })?;
        let (old, source) = self.set_value(s.key, v, None, current_actor())?;
        let value = serde_json::from_value(old).unwrap_or_else(|_| (s.default)());
        Ok(Previous { value, source })
    }

    /// Give `s` a value from below the runtime: the file's or a flag's —
    /// what the host read at start. `None` takes it away.
    pub fn seed<T: SettingValue>(&self, s: &Setting<T>, source: Source, value: Option<T>) {
        self.declare(s);
        let v = value.and_then(|v| serde_json::to_value(v).ok());
        let moved = {
            let mut entries = self.inner.entries.lock().unwrap();
            let Some(e) = entries.get_mut(s.key) else { return };
            match source {
                Source::File => e.file = v,
                Source::Flag => e.flag = v,
                Source::Default | Source::Runtime => return,
            }
            e.reapply().then(|| (e.applied.clone(), e.tx.clone(), e.hooks.clone()))
        };
        if let Some((v, tx, hooks)) = moved {
            tx.send_replace(v.clone());
            hooks.iter().for_each(|h| h(&v));
        }
    }

    /// Back to below the runtime (the flag's, the file's, the default), as
    /// the running call's caller.
    pub fn reset<T: SettingValue>(&self, s: &Setting<T>) -> Result<T, ConfigError> {
        self.declare(s);
        self.reset_key(s.key, current_actor())?;
        Ok(self.get(s))
    }

    /// Watch `s`: its value now, and every change to what is in effect.
    pub fn watch<T: SettingValue>(&self, s: &Setting<T>) -> Watch<T> {
        self.declare(s);
        let rx = self.inner.entries.lock().unwrap().get(s.key).map(|e| e.tx.subscribe()).expect("declared");
        Watch { rx, default: s.default }
    }

    /// Call `f` with `s`'s value now and at every change of it — inside the
    /// set that made it, after the store is unlocked. For a subsystem whose
    /// state follows a setting (the redactor's keys).
    pub fn on_change<T: SettingValue>(&self, s: &Setting<T>, f: impl Fn(T) + Send + Sync + 'static) {
        self.declare(s);
        let default = s.default;
        let hook: Hook = Arc::new(move |v: &Value| f(serde_json::from_value(v.clone()).unwrap_or_else(|_| default())));
        let now = {
            let mut entries = self.inner.entries.lock().unwrap();
            let e = entries.get_mut(s.key).expect("declared");
            e.hooks.push(Arc::clone(&hook));
            e.applied.clone()
        };
        hook(&now);
    }

    /// Every change, as it is made.
    pub fn changes(&self) -> tokio::sync::broadcast::Receiver<ConfigChange> {
        self.inner.changes.subscribe()
    }

    /// Every setting declared, as it stands.
    pub fn list(&self) -> Vec<KeyInfo> {
        let entries = self.inner.entries.lock().unwrap();
        entries.iter().map(|(k, e)| self.info_of(k, e)).collect()
    }

    /// One setting, as it stands.
    pub fn info(&self, key: &str) -> Option<KeyInfo> {
        let entries = self.inner.entries.lock().unwrap();
        entries.get(key).map(|e| self.info_of(key, e))
    }

    /// The keys declared.
    pub fn keys(&self) -> Vec<String> {
        self.inner.entries.lock().unwrap().keys().cloned().collect()
    }

    /// Every setting's JSON Schema, by key.
    pub fn schema(&self) -> Value {
        let entries = self.inner.entries.lock().unwrap();
        Value::Object(entries.iter().map(|(k, e)| (k.clone(), e.schema.clone())).collect())
    }

    fn info_of(&self, key: &str, e: &Entry) -> KeyInfo {
        let secret = e.sensitivity == Sensitivity::Secret;
        KeyInfo {
            key: key.to_string(),
            doc: e.doc.to_string(),
            value: (!secret).then(|| e.applied.clone()),
            hash: self.hash(e, &e.applied),
            set: e.applied_source != Source::Default,
            source: e.applied_source,
            default: (!secret).then(|| e.default.clone()),
            reload: e.reload,
            sensitivity: e.sensitivity,
            scope: e.scope,
            remote: e.remote,
            critical: e.critical,
            pending: e.pending().map(|v| if secret { Value::Null } else { v }),
            confirm_until: e.confirm.as_ref().map(|p| p.until),
            schema: e.schema.clone(),
        }
    }

    fn hash(&self, e: &Entry, v: &Value) -> String {
        let text = super::content_hash::canonical_json(v);
        match e.sensitivity {
            Sensitivity::Public => super::content_hash::hash16(text.as_bytes()),
            Sensitivity::Secret => {
                let mut b = self.inner.salt.to_vec();
                b.extend_from_slice(text.as_bytes());
                format!("salted:{}", super::content_hash::hash16(&b))
            }
        }
    }

    /// The facts the `config` activation decides on: `(remote, critical)`.
    pub fn flags(&self, key: &str) -> Option<(bool, bool)> {
        self.inner.entries.lock().unwrap().get(key).map(|e| (e.remote, e.critical))
    }

    fn unknown(&self, key: &str) -> ConfigError {
        let prefix = format!("{key}.");
        let keys = self.inner.entries.lock().unwrap().keys().filter(|k| k.starts_with(&prefix)).cloned().collect();
        ConfigError::Unknown { key: key.into(), keys }
    }

    /// The untyped set the `config` activation makes: `value` checked
    /// against the key's type, applied, stored, audited, said; with
    /// `confirm_within`, reverted unless [`Config::confirm`] comes in time.
    /// Answers the value in effect before and where it came from.
    pub fn set_value(&self, key: &str, value: Value, confirm_within: Option<Duration>, actor: Actor) -> Result<(Value, Source), ConfigError> {
        let at = now_ms();
        let (old, old_src, record, change, notify, kept) = {
            let mut entries = self.inner.entries.lock().unwrap();
            let Some(e) = entries.get_mut(key) else {
                drop(entries);
                return Err(self.unknown(key));
            };
            let value = (e.check)(value).map_err(|message| ConfigError::Invalid { key: key.into(), message })?;
            let (old, old_src) = (e.applied.clone(), e.applied_source);
            let before = e.runtime.clone();
            e.runtime = Some(value.clone());
            let confirm_until = match confirm_within {
                Some(d) => {
                    let generation = self.inner.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    let until = at + d.as_millis() as i64;
                    // A set over a waiting one keeps the revert to the
                    // value before the first.
                    let revert_to = e.confirm.take().map_or(before, |p| p.revert_to);
                    e.confirm = Some(Pending { generation, until, revert_to });
                    self.revert_after(key.to_string(), generation, d);
                    Some(until)
                }
                None => {
                    e.confirm = None;
                    None
                }
            };
            let moved = e.reapply();
            let record = ConfigRecord { action: ConfigAction::Set, key: key.into(), actor: actor.clone(), at, old_hash: Some(self.hash(e, &old)), new_hash: Some(self.hash(e, &value)), confirm_until, why: None };
            let change = self.change_of(key, e, ConfigAction::Set, actor, at, confirm_until);
            let notify = moved.then(|| (e.applied.clone(), e.tx.clone(), e.hooks.clone()));
            (old, old_src, record, change, notify, value)
        };
        let stored = self.store(key, Some(kept));
        self.after(record, change, notify);
        stored?;
        Ok((old, old_src))
    }

    /// Take a key's runtime value away, as `actor`.
    pub fn reset_key(&self, key: &str, actor: Actor) -> Result<(), ConfigError> {
        let at = now_ms();
        let (record, change, notify) = {
            let mut entries = self.inner.entries.lock().unwrap();
            let Some(e) = entries.get_mut(key) else {
                drop(entries);
                return Err(self.unknown(key));
            };
            let old = e.applied.clone();
            e.runtime = None;
            e.confirm = None;
            let moved = e.reapply();
            let record = ConfigRecord { action: ConfigAction::Reset, key: key.into(), actor: actor.clone(), at, old_hash: Some(self.hash(e, &old)), new_hash: Some(self.hash(e, &e.applied)), confirm_until: None, why: None };
            let change = self.change_of(key, e, ConfigAction::Reset, actor, at, None);
            (record, change, moved.then(|| (e.applied.clone(), e.tx.clone(), e.hooks.clone())))
        };
        let stored = self.store(key, None);
        self.after(record, change, notify);
        stored
    }

    /// Keep the change waiting on `key`: it is not reverted.
    pub fn confirm(&self, key: &str, actor: Actor) -> Result<(), ConfigError> {
        let at = now_ms();
        let (record, change) = {
            let mut entries = self.inner.entries.lock().unwrap();
            let Some(e) = entries.get_mut(key) else {
                drop(entries);
                return Err(self.unknown(key));
            };
            if e.confirm.take().is_none() {
                return Err(ConfigError::NothingToConfirm { key: key.into() });
            }
            let h = self.hash(e, &e.applied);
            let record = ConfigRecord { action: ConfigAction::Confirmed, key: key.into(), actor: actor.clone(), at, old_hash: None, new_hash: Some(h), confirm_until: None, why: None };
            (record, self.change_of(key, e, ConfigAction::Confirmed, actor, at, None))
        };
        self.after(record, change, None);
        Ok(())
    }

    /// Record a refusal the activation made (never the value).
    pub fn refused(&self, key: &str, actor: Actor, why: &str) {
        let r = ConfigRecord { action: ConfigAction::Refused, key: key.into(), actor, at: now_ms(), old_hash: None, new_hash: None, confirm_until: None, why: Some(why.into()) };
        self.audit(&r);
    }

    fn revert_after(&self, key: String, generation: u64, d: Duration) {
        let weak = self.downgrade();
        crate::rt::spawn(async move {
            crate::rt::sleep(d).await;
            if let Some(inner) = weak.upgrade() {
                Config { inner }.revert(&key, generation);
            }
        });
    }

    /// The deadline of the change `generation` on `key` passed: undo it,
    /// unless it was confirmed or another took its place.
    fn revert(&self, key: &str, generation: u64) {
        let at = now_ms();
        let (record, change, notify, stored) = {
            let mut entries = self.inner.entries.lock().unwrap();
            let Some(e) = entries.get_mut(key) else { return };
            match &e.confirm {
                Some(p) if p.generation == generation => {}
                _ => return,
            }
            let p = e.confirm.take().expect("checked");
            let old = e.applied.clone();
            e.runtime = p.revert_to.clone();
            let moved = e.reapply();
            let actor = vec!["config:revert".to_string()];
            let record = ConfigRecord { action: ConfigAction::Reverted, key: key.into(), actor: actor.clone(), at, old_hash: Some(self.hash(e, &old)), new_hash: Some(self.hash(e, &e.applied)), confirm_until: None, why: Some("not confirmed in time".into()) };
            let change = self.change_of(key, e, ConfigAction::Reverted, actor, at, None);
            (record, change, moved.then(|| (e.applied.clone(), e.tx.clone(), e.hooks.clone())), p.revert_to)
        };
        if let Err(e) = self.store(key, stored) {
            tracing::error!(target: "plexus::config", key, "{e}");
        }
        tracing::warn!(target: "plexus::config", key, "a change not confirmed in time is reverted");
        self.after(record, change, notify);
    }

    fn change_of(&self, key: &str, e: &Entry, action: ConfigAction, actor: Actor, at: i64, confirm_until: Option<i64>) -> ConfigChange {
        ConfigChange {
            action,
            key: key.into(),
            value: (e.sensitivity == Sensitivity::Public).then(|| e.applied.clone()),
            hash: self.hash(e, &e.applied),
            source: e.applied_source,
            actor,
            at,
            pending: e.pending().is_some(),
            confirm_until,
        }
    }

    fn after(&self, record: ConfigRecord, change: ConfigChange, notify: Option<(Value, tokio::sync::watch::Sender<Value>, Vec<Hook>)>) {
        self.audit(&record);
        if let Some((v, tx, hooks)) = notify {
            tx.send_replace(v.clone());
            hooks.iter().for_each(|h| h(&v));
        }
        let _ = self.inner.changes.send(change);
    }

    fn audit(&self, r: &ConfigRecord) {
        tracing::info!(
            target: "plexus::audit",
            action = ?r.action, key = %r.key, actor = %r.actor.join(" < "), at = r.at,
            old_hash = r.old_hash.as_deref().unwrap_or(""), new_hash = r.new_hash.as_deref().unwrap_or(""),
            confirm_until = r.confirm_until.unwrap_or(0), why = r.why.as_deref().unwrap_or(""),
            "config"
        );
        let sinks = self.inner.audit.lock().unwrap().clone();
        for s in sinks {
            s.record(r);
        }
    }

    /// Write `key`'s runtime value (or its absence) to the file, if there is one.
    fn store(&self, key: &str, value: Option<Value>) -> Result<(), ConfigError> {
        let Some(file) = &self.inner.file else { return Ok(()) };
        let snapshot = {
            let mut stored = self.inner.stored.lock().unwrap();
            match value {
                Some(v) => stored.insert(key.to_string(), v),
                None => stored.remove(key),
            };
            stored.clone()
        };
        write_private(file, &serde_json::to_string_pretty(&snapshot).unwrap_or_default()).map_err(|message| ConfigError::Store { message })
    }
}

/// Write `text` to `file`, 0600, whole (a temporary beside it renamed in).
fn write_private(file: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = file.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(text.as_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, file).map_err(|e| format!("{}: {e}", file.display()))
}

/// A setting watched: its value now, and each change.
pub struct Watch<T> {
    rx: tokio::sync::watch::Receiver<Value>,
    default: fn() -> T,
}

impl<T: SettingValue> Watch<T> {
    /// The value now.
    pub fn current(&self) -> T {
        serde_json::from_value(self.rx.borrow().clone()).unwrap_or_else(|_| (self.default)())
    }

    /// The next change; `None` once the store is gone.
    pub async fn changed(&mut self) -> Option<T> {
        self.rx.changed().await.ok()?;
        Some(self.current())
    }
}
