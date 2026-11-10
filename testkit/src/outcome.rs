//! What a call did, in the domain's words (KEEL-26): it **answered** — data
//! items, then `done`; it was **refused** — by the service's gate or router
//! before it opened, or in band by something past it (a child, the far
//! side of a seam); or it **failed** — the method's own error.
//!
//! ```text
//! caller.call("shop.items", json!({})).await.answers(2);
//! caller.call("shop.till", json!({})).await.refused(Forbidden).naming("shop.till");
//! caller.call("shop.add", json!({})).await.failed().saying("name");
//! ```
//!
//! Every assertion here is `#[track_caller]`: a failure points at the
//! test's line and says the method, the caller and the whole outcome.

use std::fmt;

use plexus_core::plexus::{PlexusStreamItem, RemoteError};
use plexus_core::PlexusError;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// Which refusal: what the gate or router said, as the wire's typed error
/// ([`RemoteError`]) names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// No one signed in, and the method is not public.
    Unauthenticated,
    /// Signed in, without the grant (or past the session's ceiling).
    Forbidden,
    /// No activation, or no method, by that name.
    NotFound,
    /// The params do not fit the method.
    InvalidParams,
}

impl RefusalKind {
    /// The refusal kind of a typed error, when it is a refusal.
    fn of(error: &RemoteError) -> Option<Self> {
        match error {
            RemoteError::Unauthenticated => Some(Self::Unauthenticated),
            RemoteError::Forbidden { .. } => Some(Self::Forbidden),
            RemoteError::ActivationNotFound { .. } | RemoteError::MethodNotFound { .. } => Some(Self::NotFound),
            RemoteError::InvalidParams { .. } => Some(Self::InvalidParams),
            _ => None,
        }
    }
}

/// What a call did: the items its stream sent, in order — or, if the
/// service would not open it, why (its own typed error, kept whole).
pub struct Outcome {
    method: String,
    caller: String,
    opened: Result<Vec<PlexusStreamItem>, PlexusError>,
}

impl Outcome {
    /// The outcome of `method`, called by `caller` (a name for messages):
    /// what [`Caller::call`](crate::Caller::call) returns.
    pub(crate) fn new(method: &str, caller: String, opened: Result<Vec<PlexusStreamItem>, PlexusError>) -> Self {
        Self { method: method.to_string(), caller, opened }
    }

    /// The outcome of a call that opened, from the items it sent — read off
    /// a pipe, or the rest of a stream a test held
    /// ([`Caller::stream`](crate::Caller::stream)). `caller` names who
    /// called, for the messages.
    pub fn of(method: &str, caller: &str, items: Vec<PlexusStreamItem>) -> Self {
        Self::new(method, caller.to_string(), Ok(items))
    }

    /// It answered `n` data items, then `done` — neither refused nor
    /// failed; progress is not data. Returns them.
    #[track_caller]
    pub fn answers(&self, n: usize) -> Vec<Value> {
        let data = self.items();
        if data.len() != n {
            self.fail(&format!("expected {n} data item{}, got {}", if n == 1 { "" } else { "s" }, data.len()));
        }
        data
    }

    /// It answered exactly one data item, then `done`: that item, as a `T`.
    #[track_caller]
    pub fn answer<T: DeserializeOwned>(&self) -> T {
        let one = self.answers(1).remove(0);
        match serde_json::from_value(one) {
            Ok(t) => t,
            Err(e) => self.fail(&format!("expected its answer to read as {}: {e}", std::any::type_name::<T>())),
        }
    }

    /// It answered — its stream closed with `done`, no error in it: every
    /// data item it sent, however many.
    #[track_caller]
    pub fn items(&self) -> Vec<Value> {
        let items = match &self.opened {
            Ok(items) => items,
            Err(_) => self.fail("expected an answer"),
        };
        if items.iter().any(|i| matches!(i, PlexusStreamItem::Error { .. })) {
            self.fail("expected an answer");
        }
        if !matches!(items.last(), Some(PlexusStreamItem::Done { .. })) {
            self.fail("expected an answer closed with done");
        }
        items
            .iter()
            .filter_map(|i| match i {
                PlexusStreamItem::Data { content, .. } => Some(content.clone().into_value()),
                _ => None,
            })
            .collect()
    }

    /// The service refused it before it opened — its gate or its router —
    /// for `kind`: the [`Refusal`], to read further.
    #[track_caller]
    pub fn refused(&self, kind: RefusalKind) -> Refusal {
        let error = match &self.opened {
            Err(e) => e,
            Ok(_) => self.fail(&format!("expected it refused ({kind:?}) before it opened")),
        };
        let remote = RemoteError::from(error);
        if RefusalKind::of(&remote) != Some(kind) {
            self.fail(&format!("expected it refused ({kind:?}) before it opened"));
        }
        Refusal { error: remote, message: error.to_string(), routed: Some(error.clone()), outcome: self.to_string() }
    }

    /// It opened, and its stream carried a refusal of `kind` and nothing
    /// else — a child's gate, or the far side of a seam, said no.
    #[track_caller]
    pub fn refused_in_band(&self, kind: RefusalKind) -> Refusal {
        let want = format!("expected it refused ({kind:?}) in band, the refusal its only item");
        let items = match &self.opened {
            Ok(items) => items,
            Err(_) => self.fail(&want),
        };
        match items.as_slice() {
            [item @ PlexusStreamItem::Error { error, .. }] if RefusalKind::of(error) == Some(kind) => {
                Refusal { error: error.clone(), message: said(item), routed: None, outcome: self.to_string() }
            }
            _ => self.fail(&want),
        }
    }

    /// It failed: an error that is no refusal — the method's own, or the
    /// service's in running it (a lost child, a panic).
    #[track_caller]
    pub fn failed(&self) -> Failure {
        let (error, message) = match &self.opened {
            Err(e) => (RemoteError::from(e), e.to_string()),
            Ok(items) => match items.last() {
                Some(item @ PlexusStreamItem::Error { error, .. }) => (error.clone(), said(item)),
                _ => self.fail("expected it failed"),
            },
        };
        if RefusalKind::of(&error).is_some() {
            self.fail("expected it failed, not refused");
        }
        Failure { error, message, outcome: self.to_string() }
    }

    /// Everything, as values: each data item's content, any other item as
    /// the wire writes it, the closing `done` kept — [`parts::every_item`]'s
    /// shape (a call not opened is one item, `{"route_error": <Debug>}`).
    ///
    /// [`parts::every_item`]: crate::parts::every_item
    pub fn raw(&self) -> Vec<Value> {
        match &self.opened {
            Err(e) => vec![json!({ "route_error": format!("{e:?}") })],
            Ok(items) => items.iter().map(value).collect(),
        }
    }

    /// The kit's answer before KEEL-26 — [`raw`](Self::raw) with the
    /// closing `done` left out, [`parts::items`]' shape — for the files not
    /// yet read through the outcome. One release of the kit, then gone.
    ///
    /// [`parts::items`]: crate::parts::items
    #[deprecated(note = "KEEL-26: read the outcome — answers, answer, refused, failed; raw() for every item")]
    pub fn values(&self) -> Vec<Value> {
        let mut all = self.raw();
        if self.opened.is_ok() {
            all.retain(|v| v["type"] != "done");
        }
        all
    }

    #[track_caller]
    fn fail(&self, expected: &str) -> ! {
        panic!("{expected}\n{self}")
    }
}

/// `<method> as <caller>`, then each item on its own line.
impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "  {} as {}", self.method, self.caller)?;
        match &self.opened {
            Err(e) => write!(f, " was refused before it opened: {}\n    {e}\n    {}", RemoteError::from(e).kind(), compact(&RemoteError::from(e))),
            Ok(items) => {
                write!(f, " opened, and sent {}:", if items.is_empty() { "nothing".to_string() } else { format!("{} item(s)", items.len()) })?;
                for item in items {
                    match item {
                        PlexusStreamItem::Data { content, .. } => write!(f, "\n    data      {}", content.clone().into_value())?,
                        PlexusStreamItem::Progress { content, .. } => write!(f, "\n    progress  {content}")?,
                        PlexusStreamItem::Error { error, .. } => {
                            write!(f, "\n    error     {}: {}\n              {}", error.kind(), said(item), compact(error))?
                        }
                        PlexusStreamItem::Done { .. } => write!(f, "\n    done")?,
                    }
                }
                if !matches!(items.last(), Some(PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. })) {
                    write!(f, "\n    (no done: the stream ended open)")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A call refused: of which kind, and — for the gate's `Forbidden` — the
/// grant it needed, where, the roles that list it and where the caller
/// holds it. Each check returns the refusal, to chain.
#[derive(Clone)]
pub struct Refusal {
    error: RemoteError,
    message: String,
    routed: Option<PlexusError>,
    outcome: String,
}

impl Refusal {
    /// It names `grant`: the one the caller lacks.
    #[track_caller]
    pub fn naming(self, grant: &str) -> Self {
        let got = self.missing_grant("a grant").0.to_string();
        if got != grant {
            self.fail(&format!("expected the refusal to name {grant}, it names {got}"));
        }
        self
    }

    /// It was needed at `scope`: the target's innermost scope, or `*`.
    #[track_caller]
    pub fn at(self, scope: &str) -> Self {
        let got = self.missing_grant("a scope").1.to_string();
        if got != scope {
            self.fail(&format!("expected it needed at {scope}, it was needed at {got}"));
        }
        self
    }

    /// The roles that list the grant are `roles`, in order (`admin` last).
    #[track_caller]
    pub fn listed_by<'a>(self, roles: impl IntoIterator<Item = &'a str>) -> Self {
        let want: Vec<&str> = roles.into_iter().collect();
        let got: Vec<String> = self.missing_grant("the roles listing it").2.to_vec();
        if got != want {
            self.fail(&format!("expected the grant listed by {want:?}, it is listed by {got:?}"));
        }
        self
    }

    /// The caller holds the grant on `scopes`, and nowhere else.
    #[track_caller]
    pub fn held_on<'a>(self, scopes: impl IntoIterator<Item = &'a str>) -> Self {
        let want: Vec<&str> = scopes.into_iter().collect();
        let got: Vec<String> = self.missing_grant("where it is held").3.to_vec();
        if got != want {
            self.fail(&format!("expected the grant held on {want:?}, it is held on {got:?}"));
        }
        self
    }

    /// The refusal's human line (`needs tickets.set_status on IDENTITY`).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The refusal as the wire types it.
    pub fn error(&self) -> &RemoteError {
        &self.error
    }

    /// The service's own error, when it refused before the call opened —
    /// for a test of how that error is rendered.
    pub fn plexus_error(&self) -> Option<&PlexusError> {
        self.routed.as_ref()
    }

    #[track_caller]
    fn missing_grant(&self, what: &str) -> (&String, &String, &Vec<String>, &Vec<String>) {
        match &self.error {
            RemoteError::Forbidden { reason: plexus_core::plexus::DenyReason::MissingGrant { grant, scope, roles, held_on } } => {
                (grant, scope, roles, held_on)
            }
            _ => self.fail(&format!("expected a missing grant's refusal, which names {what}")),
        }
    }

    #[track_caller]
    fn fail(&self, expected: &str) -> ! {
        panic!("{expected}\n{}", self.outcome)
    }
}

impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Refusal({}: {})", self.error.kind(), self.message)
    }
}

/// A call that failed: the error, typed, and its human line.
#[derive(Clone)]
pub struct Failure {
    error: RemoteError,
    message: String,
    outcome: String,
}

impl Failure {
    /// Its human line says `text`.
    #[track_caller]
    pub fn saying(self, text: &str) -> Self {
        if !self.message.contains(text) {
            panic!("expected the failure to say {text:?}, it says {:?}\n{}", self.message, self.outcome);
        }
        self
    }

    /// Its human line.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The failure as the wire types it.
    pub fn error(&self) -> &RemoteError {
        &self.error
    }
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failure({}: {})", self.error.kind(), self.message)
    }
}

/// An error item's human line: its `message`, or its typed error's.
fn said(item: &PlexusStreamItem) -> String {
    match item {
        PlexusStreamItem::Error { message, error, .. } if message.is_empty() => error.to_string(),
        PlexusStreamItem::Error { message, .. } => message.clone(),
        _ => String::new(),
    }
}

/// An item as values: a data item its content, any other as the wire writes it.
fn value(item: &PlexusStreamItem) -> Value {
    match item {
        PlexusStreamItem::Data { content, .. } => content.clone().into_value(),
        other => serde_json::to_value(other).unwrap_or(Value::Null),
    }
}

fn compact(error: &RemoteError) -> String {
    serde_json::to_string(error).unwrap_or_default()
}
