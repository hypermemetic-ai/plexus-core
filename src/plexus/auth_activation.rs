//! AUTH-5 — **the `auth` activation**: one auth surface in every gated
//! Plexus hub. Sign in, sign up, who am I, what does this need, and the
//! admin's roles and memberships.
//!
//! A service turns login on with [`DynamicHub::with_auth`], handing it an
//! [`AuthSetup`]: what only the service knows —
//!
//! - an [`AuthBackend`]: its providers, its login flows (the browser start
//!   and finish, a password, a session minted on a key-proved or signed-in
//!   connection), signup and the waiting list, logout;
//! - an editable [`RoleStore`] (role → grants: defaults from the
//!   activations' `roles(...)`, an admin's edits win) and
//!   [`MembershipStore`] (who holds which role where);
//! - its scope [`Resolve`]r.
//!
//! The hub builds the [`Gate`] from those same stores (so an edit reaches
//! the next call and the next view), mounts this activation, and the rest
//! the activation answers itself from the gate and the stores:
//!
//! | method | who | answers |
//! |---|---|---|
//! | `providers`, `login`, `signup` | anyone (`public`) | the door |
//! | `whoami`, `logout`, `requires` | any signed-in caller (whatever its roles or ceiling) | `whoami`, `logged_out`, `requires` |
//! | `roles` | whoever holds `auth.roles` (admin) | one `role` per role |
//! | `role_set` | admin on `*` | the role as it now stands |
//! | `grant`, `revoke` | whoever holds them on the scope (`target = "scope"`) | `granted` / `revoked` |
//! | `waiting` | admin on `*` | one `waiting` per principal asking |
//!
//! A refusal the gate makes is AUTH-2's typed error item; one this
//! activation makes (`role_set`, `waiting` short of `*`) is an in-band
//! `{type: "error", error_kind: "forbidden", grant, scope, roles,
//! held_on, message}` event — the same fields.
//!
//! [`super::auth_memory`] has a reference in-memory implementation of every
//! trait here, for tests and as a starting point.
//!
//! [`DynamicHub::with_auth`]: super::DynamicHub::with_auth

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use async_stream::stream;
use async_trait::async_trait;
use futures::Stream;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use plexus_auth_core::grants::{
    Ceiling, Gate, Grant, GrantSet, Membership, Memberships, Reach, Resolve, Roles, ScopeRef, ADMIN,
};
use plexus_auth_core::identity::Principal;
use plexus_auth_core::RoleName;

use super::auth::AuthContext;
use super::schema::{MethodRole, PluginSchema};

/// The grants every signed-in caller reaches, whatever its roles or its
/// session's ceiling: asking who it is, signing out, and asking what a
/// method needs. Never anonymously.
pub const SIGNED_IN_GRANTS: [&str; 3] = ["auth.whoami", "auth.logout", "auth.requires"];

// ===========================================================================
// Wire types
// ===========================================================================

/// How a provider signs someone in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// A person, through the browser (OIDC, WorkOS, …): `login {flow:
    /// {browser}}` then `{code}`.
    Browser,
    /// A username and password (`login {flow: {password}}`).
    Password,
    /// An agent's key: a proof at the upgrade, then `login {flow: {session}}`.
    Key,
}

/// One way in this server offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Provider {
    /// Its name (`workos`, `plexus-idp`, `key`).
    pub name: String,
    pub kind: ProviderKind,
    /// A human label, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// How a caller signs in (`auth.login {flow: …}`). On the wire, externally
/// tagged: `{"browser": {"redirect": …}}`, `{"code": {"code", "state"}}`,
/// `{"password": {"username", "password"}}`, `{"session": {"ttl_secs",
/// "ceiling"}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginFlow {
    /// A person, from a client with a browser: answered with the URL to
    /// open (`login_url {url, state}`); the browser comes back to
    /// `redirect` (a loopback address the client listens on) with a
    /// one-time code.
    Browser { redirect: String },
    /// The browser came back: trade the code for a session. Single-use,
    /// bound to the state.
    Code { code: String, state: String },
    /// Where a provider takes a password.
    Password { username: String, password: String },
    /// A session on a connection that is already someone — a key proof at
    /// the upgrade (IDENTITY-40), or a session — bounded by `ceiling`
    /// (`role@SCOPE` / `grant@SCOPE` entries) and lasting `ttl_secs`.
    Session {
        #[serde(default)]
        ttl_secs: Option<u64>,
        #[serde(default)]
        ceiling: Option<Vec<String>>,
    },
}

/// A session a backend minted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Session {
    /// The bearer token (`Authorization: Bearer …`, or the service's cookie).
    pub token: String,
    /// Who it is: `key:…`, `oidc:workos/user_…`, `idp:…`.
    pub principal: String,
    /// The agent id, for an agent's session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// A display name, when the provider gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Unix seconds.
    pub expires_at: i64,
    /// The session's ceiling, `role@SCOPE` / `grant@SCOPE`; empty: none.
    #[serde(default)]
    pub ceiling: Vec<String>,
}

/// Someone asking for access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Waiting {
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The way they came in (`key`, `workos`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Unix seconds: when they first asked.
    pub since: i64,
}

/// What `login` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginAnswer {
    /// Open this URL; the browser comes back with a code for this state.
    LoginUrl { url: String, state: String },
    Session(Session),
}

/// What `signup` answers when the backend decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignupAnswer {
    Waiting(Waiting),
    LoginUrl { url: String, state: String },
    Session(Session),
}

/// Why a backend would not: said to the caller as an in-band error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailure(pub String);

impl AuthFailure {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthFailure {}

/// Why a store would not write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// A membership as `whoami` says it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MembershipEntry {
    pub role: String,
    pub scope: String,
}

/// Every event the `auth` activation sends (`{"type": …}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthEvent {
    /// `providers`: one way in.
    Provider {
        name: String,
        kind: ProviderKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// `login {browser}` / `signup`: open this URL.
    LoginUrl { url: String, state: String },
    /// `login`: signed in.
    Session {
        token: String,
        principal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        expires_at: i64,
        #[serde(default)]
        ceiling: Vec<String>,
    },
    /// `signup` (asking for access) / `waiting` (an admin's list).
    Waiting {
        principal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        since: i64,
    },
    /// `whoami`.
    Whoami {
        principal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
        memberships: Vec<MembershipEntry>,
        ceiling: Vec<String>,
    },
    /// `logout`.
    LoggedOut { principal: String },
    /// `requires {method}`: its grant, its target, the roles that list it.
    Requires {
        method: String,
        grant: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        roles: Vec<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        public: bool,
    },
    /// `roles` / `role_set`: a role and its grants (`all`: every grant —
    /// admin).
    Role {
        role: String,
        grants: Vec<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        all: bool,
    },
    /// `grant`.
    Granted { principal: String, role: String, scope: String },
    /// `revoke`: the roles it removed there.
    Revoked { principal: String, scope: String, roles: Vec<String> },
    /// Anything refused or failed. A refusal (`error_kind: "forbidden"`)
    /// carries AUTH-2's fields.
    Error {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        held_on: Option<Vec<String>>,
    },
}

impl AuthEvent {
    fn error(message: impl Into<String>) -> Self {
        Self::Error { message: message.into(), error_kind: None, grant: None, scope: None, roles: None, held_on: None }
    }
}

impl From<Session> for AuthEvent {
    fn from(s: Session) -> Self {
        Self::Session {
            token: s.token,
            principal: s.principal,
            agent: s.agent,
            name: s.name,
            expires_at: s.expires_at,
            ceiling: s.ceiling,
        }
    }
}

impl From<Waiting> for AuthEvent {
    fn from(w: Waiting) -> Self {
        Self::Waiting { principal: w.principal, name: w.name, provider: w.provider, since: w.since }
    }
}

// ===========================================================================
// What a service supplies
// ===========================================================================

/// What only the service knows about signing in. Async: a backend may talk
/// to its identity provider. (The gate's own questions — [`Memberships`],
/// [`Roles`], [`Resolve`] — stay synchronous and from memory.)
#[async_trait]
pub trait AuthBackend: Send + Sync + 'static {
    /// The ways in this server offers (`auth.providers`).
    fn providers(&self) -> Vec<Provider>;

    /// Sign in by `flow` (`auth.login`). `caller` is the connection's
    /// identity, if any: a [`LoginFlow::Session`] needs one (a key proof at
    /// the upgrade, or a session) and must not widen it — the new
    /// session's ceiling lies within the caller's (layer it). The browser
    /// flow's start and finish, the code's single use and expiry, and the
    /// session's minting are the backend's.
    async fn login(&self, caller: Option<&AuthContext>, flow: LoginFlow) -> Result<LoginAnswer, AuthFailure>;

    /// `auth.signup` where the activation's own rule does not decide it:
    /// an anonymous caller (create an account — or refuse: sign in first),
    /// or one who already holds a membership. (A signed-in caller holding
    /// none is put on the waiting list by [`AuthBackend::ask_access`].)
    async fn signup(&self, caller: Option<&AuthContext>, via: Option<String>) -> Result<SignupAnswer, AuthFailure>;

    /// Put a signed-in caller who holds no membership on the waiting list
    /// (asking again keeps the first `since`).
    async fn ask_access(&self, caller: &AuthContext, via: Option<String>) -> Result<Waiting, AuthFailure>;

    /// Everyone who has asked for access. The activation shows an admin
    /// only those still holding no membership.
    fn waiting(&self) -> Vec<Waiting>;

    /// End the caller's session (`auth.logout`). A connection with no
    /// session to end (a bare key proof) is not an error.
    async fn logout(&self, caller: &AuthContext) -> Result<(), AuthFailure>;
}

/// [`Roles`] an admin can edit (`auth.role_set`). The gate reads the same
/// store, so an edit reaches the next call and the next view.
#[async_trait]
pub trait RoleStore: Roles + 'static {
    /// Replace `role`'s grants. Never called for [`ADMIN`].
    async fn set(&self, role: &RoleName, grants: GrantSet) -> Result<(), StoreError>;
}

/// [`Memberships`] an admin can edit (`auth.grant`, `auth.revoke`).
#[async_trait]
pub trait MembershipStore: Memberships + 'static {
    /// Add a membership (holding it already is not an error).
    async fn grant(&self, membership: Membership) -> Result<(), StoreError>;

    /// Remove `principal`'s memberships on `scope` — the one role named, or
    /// every role there. Answers the roles removed.
    async fn revoke(
        &self,
        principal: &Principal,
        role: Option<&RoleName>,
        scope: &ScopeRef,
    ) -> Result<Vec<RoleName>, StoreError>;
}

/// What [`DynamicHub::with_auth`](super::DynamicHub::with_auth) takes.
#[derive(Clone)]
pub struct AuthSetup {
    pub backend: Arc<dyn AuthBackend>,
    pub roles: Arc<dyn RoleStore>,
    pub memberships: Arc<dyn MembershipStore>,
    pub resolve: Arc<dyn Resolve>,
}

impl AuthSetup {
    pub fn new(
        backend: Arc<dyn AuthBackend>,
        roles: Arc<dyn RoleStore>,
        memberships: Arc<dyn MembershipStore>,
        resolve: Arc<dyn Resolve>,
    ) -> Self {
        Self { backend, roles, memberships, resolve }
    }
}

// ===========================================================================
// The catalog: what each method requires
// ===========================================================================

/// What one method requires, as `auth.requires` says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub grant: String,
    pub target: Option<String>,
    pub public: bool,
}

/// Every method of the hub by grant — fed as activations register.
#[derive(Clone, Default)]
pub struct Catalog(Arc<RwLock<BTreeMap<String, Requirement>>>);

impl Catalog {
    /// Add an activation's methods (not its auto-generated `schema`, which
    /// is introspection, nor its child routes).
    pub(crate) fn add(&self, schema: &PluginSchema) {
        let mut map = self.0.write().unwrap_or_else(|p| p.into_inner());
        for m in &schema.methods {
            if (m.name == "schema" && m.hash == "auto_schema") || !matches!(m.role, MethodRole::Rpc) {
                continue;
            }
            let grant = m.grant_or(&schema.namespace);
            map.insert(grant.clone(), Requirement { grant, target: m.target.clone(), public: m.public });
        }
    }

    /// The requirement of `method` (`tickets.set_status`).
    pub fn get(&self, method: &str) -> Option<Requirement> {
        self.0.read().unwrap_or_else(|p| p.into_inner()).get(method).cloned()
    }

    /// Whether `grant` names a method of this hub.
    pub fn knows(&self, grant: &str) -> bool {
        self.0.read().unwrap_or_else(|p| p.into_inner()).contains_key(grant)
    }
}

// ===========================================================================
// The activation
// ===========================================================================

/// The `auth` activation. Mounted by
/// [`DynamicHub::with_auth`](super::DynamicHub::with_auth); see the module
/// docs.
#[derive(Clone)]
pub struct Auth {
    inner: Arc<AuthInner>,
}

struct AuthInner {
    backend: Arc<dyn AuthBackend>,
    roles: Arc<dyn RoleStore>,
    memberships: Arc<dyn MembershipStore>,
    gate: Gate,
    catalog: Catalog,
}

/// The service's resolver, and `*` → `[*]` (a membership on everywhere is
/// granted and revoked like any other scope).
struct WithEverywhere(Arc<dyn Resolve>);

impl Resolve for WithEverywhere {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        if target.trim() == "*" {
            return Some(vec![ScopeRef::Everywhere]);
        }
        self.0.chain(target)
    }
}

impl Auth {
    /// The activation and the gate over the same stores.
    pub(crate) fn mount(setup: AuthSetup, catalog: Catalog) -> (Self, Gate) {
        let memberships: Arc<dyn Memberships> = setup.memberships.clone();
        let roles: Arc<dyn Roles> = setup.roles.clone();
        let gate = Gate::new(memberships, roles, Arc::new(WithEverywhere(setup.resolve)));
        let auth = Self {
            inner: Arc::new(AuthInner {
                backend: setup.backend,
                roles: setup.roles,
                memberships: setup.memberships,
                gate: gate.clone(),
                catalog,
            }),
        };
        (auth, gate)
    }
}

fn principal_of(ctx: &AuthContext) -> Option<Principal> {
    ctx.principal()
}

fn meta(ctx: &AuthContext, key: &str) -> Option<String> {
    ctx.get_metadata_string(key).filter(|s| !s.is_empty())
}

/// An in-band refusal: `grant` is needed on `*`.
fn needs_everywhere(gate: &Gate, grant: &str, reach: &Reach) -> AuthEvent {
    let g = Grant::new(grant);
    AuthEvent::Error {
        message: format!("needs {grant} on *"),
        error_kind: Some("forbidden".into()),
        grant: Some(grant.into()),
        scope: Some("*".into()),
        roles: Some(gate.roles_listing(&g).iter().map(|r| r.as_str().to_string()).collect()),
        held_on: Some(reach.held_on().iter().map(|s| s.as_str().to_string()).collect()),
    }
}

fn role_event(role: &RoleName, grants: Option<GrantSet>) -> AuthEvent {
    match grants {
        Some(GrantSet::All) => AuthEvent::Role { role: role.as_str().into(), grants: Vec::new(), all: true },
        Some(GrantSet::Listed(set)) => AuthEvent::Role {
            role: role.as_str().into(),
            grants: set.iter().map(|g| g.as_str().to_string()).collect(),
            all: false,
        },
        None => AuthEvent::Role { role: role.as_str().into(), grants: Vec::new(), all: false },
    }
}

#[plexus_macros::activation(
    namespace = "auth",
    version = "1.0.0",
    description = "Sign in, who am I, what does this need",
    roles(member = ["whoami", "logout", "requires"]),
)]
#[allow(deprecated)]
impl Auth {
    /// The ways in this server offers.
    #[plexus_macros::method(public, description = "The ways in this server offers")]
    async fn providers(&self) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let providers = self.inner.backend.providers();
        stream! {
            for p in providers {
                yield AuthEvent::Provider { name: p.name, kind: p.kind, label: p.label };
            }
        }
    }

    /// Sign in — a person through the browser (`{browser: {redirect}}`,
    /// then `{code: {code, state}}`), a password, or an agent's session on
    /// a key-proved connection (`{session: {ttl_secs, ceiling}}`).
    #[plexus_macros::method(
        public,
        description = "Sign in — a person through the browser, an agent with its key",
        params(flow = "browser {redirect} | code {code, state} | password {username, password} | session {ttl_secs?, ceiling?}")
    )]
    async fn login(&self, auth: Option<&AuthContext>, flow: LoginFlow) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let inner = self.inner.clone();
        let caller = auth.cloned();
        stream! {
            if let LoginFlow::Session { ceiling: Some(entries), .. } = &flow {
                if let Err(e) = Ceiling::parse(entries) {
                    yield AuthEvent::error(format!("ceiling: {e}"));
                    return;
                }
            }
            if matches!(flow, LoginFlow::Session { .. }) && caller.as_ref().and_then(principal_of).is_none() {
                yield AuthEvent::error("a session needs a connection that is someone: a key proof at the upgrade, or a session");
                return;
            }
            match inner.backend.login(caller.as_ref(), flow).await {
                Ok(LoginAnswer::LoginUrl { url, state }) => yield AuthEvent::LoginUrl { url, state },
                Ok(LoginAnswer::Session(s)) => yield s.into(),
                Err(e) => yield AuthEvent::error(e.0),
            }
        }
    }

    /// Create an account, or ask for access: a signed-in caller holding no
    /// membership joins the waiting list for an admin.
    #[plexus_macros::method(
        public,
        description = "Create an account, or ask for access",
        params(via = "The provider to sign up through, where the server offers several")
    )]
    async fn signup(&self, auth: Option<&AuthContext>, via: Option<String>) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let inner = self.inner.clone();
        let caller = auth.cloned();
        stream! {
            let holds_none = caller
                .as_ref()
                .and_then(principal_of)
                .map(|p| inner.memberships.held(&p).is_empty());
            let answer = match (holds_none, caller.as_ref()) {
                (Some(true), Some(ctx)) => inner.backend.ask_access(ctx, via).await.map(SignupAnswer::Waiting),
                _ => inner.backend.signup(caller.as_ref(), via).await,
            };
            match answer {
                Ok(SignupAnswer::Waiting(w)) => yield w.into(),
                Ok(SignupAnswer::LoginUrl { url, state }) => yield AuthEvent::LoginUrl { url, state },
                Ok(SignupAnswer::Session(s)) => yield s.into(),
                Err(e) => yield AuthEvent::error(e.0),
            }
        }
    }

    /// Who this connection is: principal, name, the roles it holds where,
    /// and its session's ceiling.
    #[plexus_macros::method(description = "Who you are: principal, roles held where, ceiling")]
    async fn whoami(&self, auth: &AuthContext) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let inner = self.inner.clone();
        let ctx = auth.clone();
        stream! {
            let Some(p) = principal_of(&ctx) else {
                yield AuthEvent::error("sign in first");
                return;
            };
            let memberships = inner
                .memberships
                .held(&p)
                .into_iter()
                .map(|m| MembershipEntry { role: m.role.as_str().into(), scope: m.scope.as_str().into() })
                .collect();
            let ceiling = Ceiling::layers_of(&ctx)
                .map(|layers| layers.iter().flat_map(|l| l.text()).collect())
                .unwrap_or_default();
            yield AuthEvent::Whoami {
                principal: p.to_string(),
                name: meta(&ctx, "name"),
                agent: meta(&ctx, "agent"),
                memberships,
                ceiling,
            };
        }
    }

    /// End this session.
    #[plexus_macros::method(description = "Sign out: end this session")]
    async fn logout(&self, auth: &AuthContext) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let inner = self.inner.clone();
        let ctx = auth.clone();
        stream! {
            let principal = principal_of(&ctx).map(|p| p.to_string()).unwrap_or_default();
            match inner.backend.logout(&ctx).await {
                Ok(()) => yield AuthEvent::LoggedOut { principal },
                Err(e) => yield AuthEvent::error(e.0),
            }
        }
    }

    /// What a method needs: its grant, its target and the roles that list
    /// it.
    #[plexus_macros::method(
        description = "What a method needs: its grant, target, and the roles that list it",
        params(method = "The method, as <activation>.<method>: tickets.set_status")
    )]
    async fn requires(&self, auth: &AuthContext, method: String) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let _ = auth;
        let inner = self.inner.clone();
        stream! {
            match inner.catalog.get(method.trim()) {
                None => yield AuthEvent::error(format!("no method {method} here")),
                Some(req) => {
                    let roles = inner.gate.roles_listing(&Grant::new(req.grant.clone()));
                    yield AuthEvent::Requires {
                        method: method.trim().to_string(),
                        grant: req.grant,
                        target: req.target,
                        roles: roles.iter().map(|r| r.as_str().to_string()).collect(),
                        public: req.public,
                    };
                }
            }
        }
    }

    /// Every role and the grants it lists (admin: every grant).
    #[plexus_macros::method(description = "Every role and the grants it lists")]
    async fn roles(&self, auth: &AuthContext) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let _ = auth;
        let inner = self.inner.clone();
        stream! {
            let admin = RoleName::new(ADMIN);
            yield role_event(&admin, Some(GrantSet::All));
            let names: BTreeSet<RoleName> = inner.roles.names().into_iter().filter(|r| r.as_str() != ADMIN).collect();
            for r in names {
                let grants = inner.roles.grants(&r);
                yield role_event(&r, grants);
            }
        }
    }

    /// Set a role's grants (admin on `*`). Each entry a grant
    /// (`tickets.get`) or an existing role whose grants it includes.
    #[plexus_macros::method(
        description = "Set a role's grants (admin on *)",
        params(role = "The role (not admin)", grants = "Grants (tickets.get) or roles to include")
    )]
    async fn role_set(&self, auth: &AuthContext, reach: Reach, role: String, grants: Vec<String>) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let _ = auth;
        let inner = self.inner.clone();
        stream! {
            if !reach.is_everywhere() {
                yield needs_everywhere(&inner.gate, "auth.role_set", &reach);
                return;
            }
            let role = role.trim().to_string();
            if role.is_empty() || role.contains('.') || role.contains('@') {
                yield AuthEvent::error(format!("`{role}` is not a role name"));
                return;
            }
            if role == ADMIN {
                yield AuthEvent::error("admin holds every grant; it is not edited");
                return;
            }
            let mut set: BTreeSet<Grant> = BTreeSet::new();
            for entry in grants.iter().map(|g| g.trim()).filter(|g| !g.is_empty()) {
                if entry.contains('.') {
                    if !inner.catalog.knows(entry) {
                        yield AuthEvent::error(format!("no method {entry} here"));
                        return;
                    }
                    set.insert(Grant::new(entry));
                } else {
                    match inner.roles.grants(&RoleName::new(entry)) {
                        Some(GrantSet::Listed(included)) => set.extend(included),
                        Some(GrantSet::All) => {
                            yield AuthEvent::error(format!("{entry} holds every grant; a role cannot include it"));
                            return;
                        }
                        None => {
                            yield AuthEvent::error(format!("no role {entry} to include"));
                            return;
                        }
                    }
                }
            }
            let name = RoleName::new(role.clone());
            if let Err(e) = inner.roles.set(&name, GrantSet::Listed(set)).await {
                yield AuthEvent::error(e.0);
                return;
            }
            let now = inner.roles.grants(&name);
            yield role_event(&name, now);
        }
    }

    /// Give `principal` `role` on `scope` (whoever holds `auth.grant` on
    /// the scope: admin there).
    #[plexus_macros::method(
        target = "scope",
        description = "Give a principal a role on a scope",
        params(principal = "key:…, oidc:…/…, idp:…", role = "The role", scope = "Where: a scope name, or *")
    )]
    async fn grant(&self, auth: &AuthContext, principal: String, role: String, scope: String) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let _ = auth;
        let inner = self.inner.clone();
        stream! {
            let who: Principal = match principal.trim().parse() {
                Ok(p) => p,
                Err(e) => {
                    yield AuthEvent::error(format!("`{principal}` is not a principal: {e}"));
                    return;
                }
            };
            let role_name = RoleName::new(role.trim());
            if role_name.as_str() != ADMIN && inner.roles.grants(&role_name).is_none() {
                yield AuthEvent::error(format!("no role {role} here"));
                return;
            }
            let scope_ref = ScopeRef::parse(&scope);
            let m = Membership { principal: who.clone(), role: role_name.clone(), scope: scope_ref.clone() };
            match inner.memberships.grant(m).await {
                Ok(()) => yield AuthEvent::Granted {
                    principal: who.to_string(),
                    role: role_name.as_str().into(),
                    scope: scope_ref.as_str().into(),
                },
                Err(e) => yield AuthEvent::error(e.0),
            }
        }
    }

    /// Take `principal`'s role (or every role) on `scope` away.
    #[plexus_macros::method(
        target = "scope",
        description = "Take a principal's role on a scope away",
        params(principal = "key:…, oidc:…/…, idp:…", role = "The role; absent: every role there", scope = "Where: a scope name, or *")
    )]
    async fn revoke(&self, auth: &AuthContext, principal: String, role: Option<String>, scope: String) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let _ = auth;
        let inner = self.inner.clone();
        stream! {
            let who: Principal = match principal.trim().parse() {
                Ok(p) => p,
                Err(e) => {
                    yield AuthEvent::error(format!("`{principal}` is not a principal: {e}"));
                    return;
                }
            };
            let scope_ref = ScopeRef::parse(&scope);
            let role_name = role.as_deref().map(|r| RoleName::new(r.trim()));
            match inner.memberships.revoke(&who, role_name.as_ref(), &scope_ref).await {
                Ok(removed) => yield AuthEvent::Revoked {
                    principal: who.to_string(),
                    scope: scope_ref.as_str().into(),
                    roles: removed.iter().map(|r| r.as_str().to_string()).collect(),
                },
                Err(e) => yield AuthEvent::error(e.0),
            }
        }
    }

    /// Who signed up or asked for access and holds nothing yet (admin on
    /// `*`).
    #[plexus_macros::method(description = "Who asked for access and holds nothing yet (admin on *)")]
    async fn waiting(&self, auth: &AuthContext, reach: Reach) -> impl Stream<Item = AuthEvent> + Send + 'static {
        let _ = auth;
        let inner = self.inner.clone();
        stream! {
            if !reach.is_everywhere() {
                yield needs_everywhere(&inner.gate, "auth.waiting", &reach);
                return;
            }
            for w in inner.backend.waiting() {
                let still = w
                    .principal
                    .parse::<Principal>()
                    .map(|p| inner.memberships.held(&p).is_empty())
                    .unwrap_or(true);
                if still {
                    yield w.into();
                }
            }
        }
    }
}
