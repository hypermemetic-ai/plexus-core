//! NEST-21 · the `config` activation: a service's settings over Plexus.
//!
//! ```text
//! config.list                          every setting, as it stands
//! config.watch { key? }                each change, as it is made (open-ended)
//! config.names                         the first segments (the slot's names)
//! config.{key}.get                     one setting
//! config.{key}.set { value, confirm_within? }
//! config.{key}.reset                   back to the flag's, the file's or the default
//! config.{key}.confirm                 keep a change made with confirm_within
//! ```
//!
//! A key is a path of dynamic children (`config.transport.insecure_ws.set`):
//! the slot `config.{key}` is typed (each method its grant,
//! `config.{key}.set`); below it the slot repeats its own type, so it is
//! untyped there (`config.{key}.{key}`, every method). Admin holds all of
//! them; a role holds one key's method by listing its path
//! (`config.transport.insecure_ws.get`), the literal grant NEST-5 keeps.
//!
//! Over the wire a setting declared `remote = false` is refused
//! (`not_remote`); a `critical` one needs the grant [`CRITICAL_GRANT`]
//! (admin's unless a role lists it) and a `confirm_within` (SIGN-1 turns
//! this into a signed call). A secret is never read back.

use async_stream::stream;
use futures::Stream;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{current_actor, parse_duration, Config, ConfigChange, ConfigError, KeyInfo, Source};
use crate::plexus::AuthContext;

/// The grant a critical setting's set, reset and confirm need beside the
/// key's own: listed by no role, so an admin's alone. SIGN-1's
/// `signed(hardware, uv)` takes its place.
pub const CRITICAL_GRANT: &str = "config.critical";

/// Why the `config` activation refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigRefusal {
    /// No setting has this key.
    UnknownKey,
    /// A prefix of keys, not a key.
    NotAKey,
    /// The value does not fit the key's type (or `confirm_within` is not a
    /// duration).
    Invalid,
    /// Declared `remote = false`: the host's code or file alone sets it.
    NotRemote,
    /// A critical setting: an admin's (`config.critical`).
    Critical,
    /// A critical setting is set as a confirmed commit (`confirm_within`).
    ConfirmRequired,
    /// Nothing waits to be confirmed.
    NothingToConfirm,
    /// The store's file could not be written (the change is in effect).
    Store,
}

/// What the `config` activation answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SettingEvent {
    /// A setting as it stands.
    Setting(KeyInfo),
    /// Set: what was in effect before (a secret's hash only) and what is
    /// now; `confirm_until` when it reverts unless confirmed.
    Set {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous: Option<Value>,
        previous_hash: String,
        previous_source: Source,
        setting: KeyInfo,
    },
    /// Back to below the runtime.
    Reset { setting: KeyInfo },
    /// The change waiting on `key` is kept.
    Confirmed { key: String },
    /// Refused, and why in a word.
    Refused { reason: ConfigRefusal, key: String, message: String },
    /// Why not.
    Error { message: String },
}

impl plexus_client::FromClientError for SettingEvent {
    fn from_client_error(e: plexus_client::ClientError) -> Self {
        SettingEvent::Error { message: e.to_string() }
    }
}

fn refused(reason: ConfigRefusal, key: &str, message: impl Into<String>) -> SettingEvent {
    SettingEvent::Refused { reason, key: key.into(), message: message.into() }
}

fn of_error(e: ConfigError) -> SettingEvent {
    let reason = match &e {
        ConfigError::Unknown { keys, .. } if !keys.is_empty() => ConfigRefusal::NotAKey,
        ConfigError::Unknown { .. } => ConfigRefusal::UnknownKey,
        ConfigError::Invalid { .. } => ConfigRefusal::Invalid,
        ConfigError::NothingToConfirm { .. } => ConfigRefusal::NothingToConfirm,
        ConfigError::Store { .. } => ConfigRefusal::Store,
    };
    let key = match &e {
        ConfigError::Unknown { key, .. } | ConfigError::Invalid { key, .. } | ConfigError::NothingToConfirm { key } => key.clone(),
        ConfigError::Store { .. } => String::new(),
    };
    refused(reason, &key, e.to_string())
}

/// The names one level below `prefix` (`""`: the first segments).
fn names_below(config: &Config, prefix: &str) -> Vec<String> {
    let mut out: Vec<String> = config
        .keys()
        .into_iter()
        .filter_map(|k| {
            let rest = if prefix.is_empty() { Some(k.as_str()) } else { k.strip_prefix(prefix).and_then(|r| r.strip_prefix('.')) }?;
            Some(rest.split('.').next().unwrap_or(rest).to_string())
        })
        .collect();
    out.dedup();
    out
}

/// The `config` activation: a service's settings, each key a dynamic child.
#[derive(Clone)]
pub struct ConfigActivation {
    config: Config,
}

impl ConfigActivation {
    /// Serve `config` (the service's: [`DynamicHub::config`]).
    ///
    /// [`DynamicHub::config`]: crate::plexus::DynamicHub::config
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// The store it serves.
    pub fn config(&self) -> &Config {
        &self.config
    }

    fn node(&self, name: &str) -> Option<ConfigKeyActivation> {
        let path = name.to_string();
        let prefix = format!("{path}.");
        self.config.keys().iter().any(|k| *k == path || k.starts_with(&prefix)).then(|| ConfigKeyActivation { config: self.config.clone(), path })
    }
}

/// A service's settings: read, set, reset and watch them, each key on its
/// own grant.
#[plexus_macros::activation(namespace = "config", description = "A service's settings at runtime: each key a node, on its own grant")]
impl ConfigActivation {
    /// Every setting, as it stands (a secret as set or not and a hash).
    #[plexus_macros::method]
    pub async fn list(&self) -> impl Stream<Item = KeyInfo> + Send + 'static {
        futures::stream::iter(self.config.list())
    }

    /// Each change as it is made — set, reset, confirmed, reverted — of
    /// every setting, or of `key` and the keys under it. Open-ended.
    #[plexus_macros::method]
    pub async fn watch(&self, key: Option<String>) -> impl Stream<Item = ConfigChange> + Send + 'static {
        let mut rx = self.config.changes();
        stream! {
            loop {
                match rx.recv().await {
                    Ok(c) => {
                        if key.as_deref().is_none_or(|k| c.key == k || c.key.starts_with(&format!("{k}."))) {
                            yield c;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    /// The first segments of the keys: the slot's names.
    #[plexus_macros::method]
    pub async fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::iter(names_below(&self.config, ""))
    }

    /// A setting, or a group of them: `config.<segment>…`.
    #[plexus_macros::child(list = names)]
    fn key(&self, name: &str) -> Option<ConfigKeyActivation> {
        self.node(name)
    }
}

/// One node of the key tree: a setting (`transport.insecure_ws`) or a group
/// of them (`transport`).
#[derive(Clone)]
pub struct ConfigKeyActivation {
    config: Config,
    path: String,
}

impl ConfigKeyActivation {
    /// The dotted path it stands for.
    pub fn path(&self) -> &str {
        &self.path
    }

    fn is_key(&self) -> Result<(bool, bool), SettingEvent> {
        match self.config.flags(&self.path) {
            Some(f) => Ok(f),
            None => Err(of_error(ConfigError::Unknown { key: self.path.clone(), keys: self.config.keys().into_iter().filter(|k| k.starts_with(&format!("{}.", self.path))).collect() })),
        }
    }

    /// A write over the wire: refused for a `remote = false` key, and for a
    /// critical one unless the caller holds [`CRITICAL_GRANT`] (and, for a
    /// set, gives `confirm_within`).
    fn may_write(&self, auth: Option<&AuthContext>, confirming: Option<bool>) -> Result<(), SettingEvent> {
        let (remote, critical) = self.is_key()?;
        let refuse = |reason, why: String| {
            self.config.refused(&self.path, current_actor(), &why);
            Err(refused(reason, &self.path, why))
        };
        if !remote {
            return refuse(ConfigRefusal::NotRemote, format!("`{}` is not settable over the wire: the host's code or its file sets it", self.path));
        }
        if critical {
            if !holds_critical(auth) {
                return refuse(ConfigRefusal::Critical, format!("`{}` is critical: an admin's (the grant `{CRITICAL_GRANT}`)", self.path));
            }
            if confirming == Some(false) {
                return refuse(ConfigRefusal::ConfirmRequired, format!("`{}` is critical: set it with confirm_within (a confirmed commit), then confirm", self.path));
            }
        }
        Ok(())
    }

    fn info(&self) -> KeyInfo {
        self.config.info(&self.path).expect("a key")
    }
}

/// Whether the caller holds [`CRITICAL_GRANT`] by the service's gate (a
/// service without one admits every call, as it always has).
fn holds_critical(auth: Option<&AuthContext>) -> bool {
    let gate = crate::plexus::service_scope::current().and_then(|w| w.upgrade()).and_then(|s| s.gate().cloned());
    match gate {
        None => true,
        Some(g) => g.check(auth, &plexus_auth_core::grants::Grant::new(CRITICAL_GRANT), None).is_ok(),
    }
}

/// A setting (or a group of them).
#[plexus_macros::activation(namespace = "config_key", description = "A setting: get, set, reset, confirm")]
impl ConfigKeyActivation {
    /// The setting as it stands: its value (a secret's hash only), where it
    /// comes from, its default, how it reloads, its type's schema.
    #[plexus_macros::method]
    pub async fn get(&self) -> SettingEvent {
        match self.is_key() {
            Ok(_) => SettingEvent::Setting(self.info()),
            Err(e) => e,
        }
    }

    /// Set it at runtime. `value` in the setting's type (a string is read
    /// as JSON when it does not fit as text: `--value true`).
    /// `confirm_within` (`60s`): applied at once, reverted unless
    /// `confirm` comes in time — so a change that cuts the caller off undoes
    /// itself.
    #[plexus_macros::method]
    pub async fn set(&self, auth: Option<&AuthContext>, value: Value, confirm_within: Option<String>) -> SettingEvent {
        let within = match confirm_within.as_deref().map(parse_duration).transpose() {
            Ok(w) => w,
            Err(why) => return refused(ConfigRefusal::Invalid, &self.path, format!("confirm_within: {why}")),
        };
        if let Err(e) = self.may_write(auth, Some(within.is_some())) {
            return e;
        }
        match self.config.set_value(&self.path, value, within, current_actor()) {
            Ok((previous, previous_source)) => {
                let setting = self.info();
                let secret = setting.value.is_none();
                let previous_hash = if secret { String::new() } else { crate::plexus::content_hash::hash16(crate::plexus::content_hash::canonical_json(&previous).as_bytes()) };
                SettingEvent::Set { key: self.path.clone(), previous: (!secret).then_some(previous), previous_hash, previous_source, setting }
            }
            Err(e) => of_error(e),
        }
    }

    /// Take its runtime value away: back to the flag's, the file's or the
    /// default.
    #[plexus_macros::method]
    pub async fn reset(&self, auth: Option<&AuthContext>) -> SettingEvent {
        if let Err(e) = self.may_write(auth, None) {
            return e;
        }
        match self.config.reset_key(&self.path, current_actor()) {
            Ok(()) => SettingEvent::Reset { setting: self.info() },
            Err(e) => of_error(e),
        }
    }

    /// Keep the change made with `confirm_within`.
    #[plexus_macros::method]
    pub async fn confirm(&self, auth: Option<&AuthContext>) -> SettingEvent {
        if let Err(e) = self.may_write(auth, None) {
            return e;
        }
        match self.config.confirm(&self.path, current_actor()) {
            Ok(()) => SettingEvent::Confirmed { key: self.path.clone() },
            Err(e) => of_error(e),
        }
    }

    /// The names one level below it.
    #[plexus_macros::method]
    pub async fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::iter(names_below(&self.config, &self.path))
    }

    /// The next segment of a key below it.
    #[plexus_macros::child(list = names)]
    fn key(&self, name: &str) -> Option<ConfigKeyActivation> {
        let path = format!("{}.{name}", self.path);
        let prefix = format!("{path}.");
        self.config.keys().iter().any(|k| *k == path || k.starts_with(&prefix)).then(|| ConfigKeyActivation { config: self.config.clone(), path })
    }
}
