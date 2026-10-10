//! AUTH-5 — a **reference, in-memory** implementation of what a service
//! supplies the `auth` activation: [`MemoryRoles`] ([`RoleStore`]),
//! [`MemoryMemberships`] ([`MembershipStore`]) and [`MemoryAuthBackend`]
//! ([`AuthBackend`], and a [`SessionValidator`] for the tokens it mints).
//!
//! For tests, and as the shape a Plexus service starts from: a real service
//! keeps the same answers in its own store (menger: its members table and
//! sessions, AUTH-7) — reads from memory, writes through.
//!
//! The backend's flows:
//!
//! - **browser** — `login {browser: {redirect}}` keeps a state for the
//!   loopback `redirect` (only `http://127.0.0.1:…` / `http://localhost:…`)
//!   and answers `{login_url: "<login_url>?cli=1&state=…", state}`. The
//!   service's web sign-in, once the person is through, calls
//!   [`MemoryAuthBackend::complete_browser`], which mints a one-time code
//!   (good for a minute) and gives the URL to send the browser back to.
//!   `login {code: {code, state}}` trades it for a session.
//! - **password** — users added with [`MemoryAuthBackend::with_user`].
//! - **session** — on a connection that is someone: a session for the same
//!   principal (and agent), its ceiling layered on the caller's.
//!
//! Tokens are `mgs_<32 hex>`; [`SessionValidator::validate`] takes the bare
//! token, `Bearer <token>`, or a `Cookie` header holding `access_token=…`.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use plexus_auth_core::grants::{Ceiling, GrantSet, Membership, Memberships, RoleTable, Roles, ScopeRef, CEILING_KEY};
use plexus_auth_core::identity::Principal;
use plexus_auth_core::{RoleName, SessionValidator};

use super::auth::AuthContext;
use super::auth_activation::{
    AuthBackend, AuthFailure, LoginAnswer, LoginFlow, MembershipStore, Provider, ProviderKind, RoleStore, Session,
    SignupAnswer, StoreError, Waiting,
};

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn fresh(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
}

// ===========================================================================
// Roles
// ===========================================================================

/// An editable [`RoleTable`]: the activations' declared defaults, an admin's
/// edits replacing a role outright.
#[derive(Debug, Default)]
pub struct MemoryRoles {
    table: RwLock<RoleTable>,
}

impl MemoryRoles {
    pub fn new(table: RoleTable) -> Self {
        Self { table: RwLock::new(table) }
    }

    /// Seeded from [`DynamicHub::declared_roles`](super::DynamicHub::declared_roles)
    /// — every activation's `roles(...)`, merged by name.
    pub fn from_declared(declared: &std::collections::BTreeMap<String, Vec<String>>) -> Self {
        Self::new(RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str)))))
    }

    /// Add the declared defaults of roles this table does not hold yet —
    /// a role already defined (or edited) keeps what it has. For a hub
    /// built before its roles are known:
    /// `roles.seed(&hub.declared_roles())` after
    /// [`DynamicHub::with_auth`](super::DynamicHub::with_auth).
    pub fn seed(&self, declared: &std::collections::BTreeMap<String, Vec<String>>) {
        let mut table = self.table.write().unwrap_or_else(|p| p.into_inner());
        let known = table.names();
        for (role, grants) in declared {
            if role == plexus_auth_core::grants::ADMIN || known.iter().any(|k| k.as_str() == role) {
                continue;
            }
            table.set(role, GrantSet::listed(grants.iter().cloned()));
        }
    }
}

impl Roles for MemoryRoles {
    fn grants(&self, role: &RoleName) -> Option<GrantSet> {
        self.table.read().unwrap_or_else(|p| p.into_inner()).grants(role)
    }

    fn names(&self) -> Vec<RoleName> {
        self.table.read().unwrap_or_else(|p| p.into_inner()).names()
    }
}

#[async_trait]
impl RoleStore for MemoryRoles {
    async fn set(&self, role: &RoleName, grants: GrantSet) -> Result<(), StoreError> {
        self.table.write().unwrap_or_else(|p| p.into_inner()).set(role.as_str(), grants);
        Ok(())
    }
}

// ===========================================================================
// Memberships
// ===========================================================================

/// Memberships as a list.
#[derive(Debug, Default)]
pub struct MemoryMemberships {
    rows: RwLock<Vec<Membership>>,
}

impl MemoryMemberships {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `principal` as `role` on `scope` (`*` or a name). Panics on a
    /// principal that does not parse — a fixture's mistake.
    pub fn with(self, principal: &str, role: &str, scope: &str) -> Self {
        self.rows.write().unwrap_or_else(|p| p.into_inner()).push(Membership {
            principal: principal.parse().expect("a principal"),
            role: RoleName::new(role),
            scope: ScopeRef::parse(scope),
        });
        self
    }

    /// Every membership.
    pub fn all(&self) -> Vec<Membership> {
        self.rows.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Memberships for MemoryMemberships {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        self.rows.read().unwrap_or_else(|p| p.into_inner()).iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

#[async_trait]
impl MembershipStore for MemoryMemberships {
    async fn grant(&self, membership: Membership) -> Result<(), StoreError> {
        let mut rows = self.rows.write().unwrap_or_else(|p| p.into_inner());
        if !rows.contains(&membership) {
            rows.push(membership);
        }
        Ok(())
    }

    async fn revoke(
        &self,
        principal: &Principal,
        role: Option<&RoleName>,
        scope: &ScopeRef,
    ) -> Result<Vec<RoleName>, StoreError> {
        let mut rows = self.rows.write().unwrap_or_else(|p| p.into_inner());
        let mut removed = Vec::new();
        rows.retain(|m| {
            let hit = &m.principal == principal && &m.scope == scope && role.is_none_or(|r| &m.role == r);
            if hit {
                removed.push(m.role.clone());
            }
            !hit
        });
        Ok(removed)
    }
}

// ===========================================================================
// Backend
// ===========================================================================

#[derive(Debug, Clone)]
struct User {
    password: String,
    principal: Principal,
    name: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionRec {
    id: String,
    principal: Principal,
    name: Option<String>,
    agent: Option<String>,
    expires_at: i64,
    layers: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Code {
    state: String,
    principal: Principal,
    name: Option<String>,
    issued: i64,
}

#[derive(Debug, Default)]
struct State {
    users: HashMap<String, User>,
    sessions: HashMap<String, SessionRec>,
    /// state → the loopback redirect it was started for
    pending: HashMap<String, String>,
    codes: HashMap<String, Code>,
    waiting: Vec<Waiting>,
}

/// An in-memory [`AuthBackend`] and [`SessionValidator`]. See the module
/// docs for its flows.
#[derive(Debug)]
pub struct MemoryAuthBackend {
    login_url: String,
    providers: Vec<Provider>,
    default_ttl: u64,
    state: Mutex<State>,
}

/// How long a browser flow's code is good for.
pub const CODE_TTL_SECS: i64 = 60;

impl MemoryAuthBackend {
    /// A backend whose browser sign-in page is `login_url` (the service's
    /// own, e.g. `http://127.0.0.1:4456/login`). Offers a `browser` and a
    /// `key` provider; [`Self::with_user`] adds `password`.
    pub fn new(login_url: impl Into<String>) -> Self {
        Self {
            login_url: login_url.into(),
            providers: vec![
                Provider { name: "browser".into(), kind: ProviderKind::Browser, label: Some("Sign in with the browser".into()) },
                Provider { name: "key".into(), kind: ProviderKind::Key, label: Some("An agent's key".into()) },
            ],
            default_ttl: 12 * 3600,
            state: Mutex::new(State::default()),
        }
    }

    /// Replace the providers offered.
    pub fn with_providers(mut self, providers: Vec<Provider>) -> Self {
        self.providers = providers;
        self
    }

    /// A password user: `username` / `password` sign in as `principal`.
    pub fn with_user(self, username: &str, password: &str, principal: &str, name: Option<&str>) -> Self {
        {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.users.insert(
                username.into(),
                User { password: password.into(), principal: principal.parse().expect("a principal"), name: name.map(Into::into) },
            );
        }
        if !self.providers.iter().any(|p| p.kind == ProviderKind::Password) {
            let mut me = self;
            me.providers.push(Provider { name: "password".into(), kind: ProviderKind::Password, label: None });
            return me;
        }
        self
    }

    /// The service's web sign-in, once the person behind `state` is through:
    /// a one-time code for that state, and the loopback URL to send the
    /// browser back to (`<redirect>?code=…&state=…`).
    pub fn complete_browser(&self, state: &str, principal: &str, name: Option<&str>) -> Result<(String, String), AuthFailure> {
        let principal: Principal = principal.parse().map_err(|e| AuthFailure::new(format!("{e}")))?;
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let redirect = st.pending.remove(state).ok_or_else(|| AuthFailure::new("no sign-in waits on this state"))?;
        let code = fresh("c_");
        st.codes.insert(code.clone(), Code { state: state.into(), principal, name: name.map(Into::into), issued: now() });
        let sep = if redirect.contains('?') { '&' } else { '?' };
        Ok((format!("{redirect}{sep}code={code}&state={state}"), code))
    }

    /// Mint a session (also what a service's own web login would call).
    pub fn mint(
        &self,
        principal: &Principal,
        name: Option<String>,
        agent: Option<String>,
        ttl_secs: Option<u64>,
        layers: Vec<Vec<String>>,
    ) -> Session {
        let token = fresh("mgs_");
        let expires_at = now() + ttl_secs.unwrap_or(self.default_ttl) as i64;
        let rec = SessionRec {
            id: fresh("sess_"),
            principal: principal.clone(),
            name: name.clone(),
            agent: agent.clone(),
            expires_at,
            layers: layers.clone(),
        };
        self.state.lock().unwrap_or_else(|p| p.into_inner()).sessions.insert(token.clone(), rec);
        Session {
            token,
            principal: principal.to_string(),
            agent,
            name,
            expires_at,
            ceiling: layers.last().cloned().unwrap_or_default(),
        }
    }

    /// The identity a token stands for, while it lasts.
    pub fn context_of(&self, token: &str) -> Option<AuthContext> {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let rec = st.sessions.get(token)?;
        if rec.expires_at <= now() {
            return None;
        }
        let mut meta = serde_json::Map::new();
        if let Some(n) = &rec.name {
            meta.insert("name".into(), n.clone().into());
        }
        if let Some(a) = &rec.agent {
            meta.insert("agent".into(), a.clone().into());
        }
        if !rec.layers.is_empty() {
            meta.insert(CEILING_KEY.into(), serde_json::json!(rec.layers));
        }
        meta.insert("expires_at".into(), rec.expires_at.into());
        Some(AuthContext::for_principal(&rec.principal, rec.id.clone(), vec![], serde_json::Value::Object(meta)))
    }

    /// The token a credential carries: bare, `Bearer …`, or a cookie
    /// header's `access_token=…`.
    fn token_in(credential: &str) -> Option<&str> {
        let c = credential.trim();
        if let Some(t) = c.strip_prefix("Bearer ") {
            return Some(t.trim());
        }
        if c.starts_with("mgs_") && !c.contains(';') && !c.contains('=') {
            return Some(c);
        }
        c.split(';').filter_map(|kv| kv.trim().split_once('=')).find(|(k, _)| *k == "access_token").map(|(_, v)| v.trim())
    }
}

/// The ceiling layers a caller's session already carries, as text.
fn layers_of(ctx: &AuthContext) -> Result<Vec<Vec<String>>, AuthFailure> {
    Ceiling::layers_of(ctx).map(|ls| ls.iter().map(|l| l.text()).collect()).map_err(|e| AuthFailure::new(e.to_string()))
}

#[async_trait]
impl AuthBackend for MemoryAuthBackend {
    fn providers(&self) -> Vec<Provider> {
        self.providers.clone()
    }

    async fn login(&self, caller: Option<&AuthContext>, flow: LoginFlow) -> Result<LoginAnswer, AuthFailure> {
        match flow {
            LoginFlow::Browser { redirect } => {
                let loopback = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"];
                if !loopback.iter().any(|p| redirect.starts_with(p)) {
                    return Err(AuthFailure::new("the redirect must be a loopback address (http://127.0.0.1:PORT/…)"));
                }
                let state = fresh("s_");
                self.state.lock().unwrap_or_else(|p| p.into_inner()).pending.insert(state.clone(), redirect);
                let sep = if self.login_url.contains('?') { '&' } else { '?' };
                Ok(LoginAnswer::LoginUrl { url: format!("{}{sep}cli=1&state={state}", self.login_url), state })
            }
            LoginFlow::Code { code, state } => {
                let found = self.state.lock().unwrap_or_else(|p| p.into_inner()).codes.remove(&code);
                let Some(c) = found else { return Err(AuthFailure::new("the code is not good (used, or never issued)")) };
                if c.state != state {
                    return Err(AuthFailure::new("the code is not good for this state"));
                }
                if now() - c.issued > CODE_TTL_SECS {
                    return Err(AuthFailure::new("the code has expired: sign in again"));
                }
                Ok(LoginAnswer::Session(self.mint(&c.principal, c.name, None, None, Vec::new())))
            }
            LoginFlow::Password { username, password } => {
                let user = self.state.lock().unwrap_or_else(|p| p.into_inner()).users.get(&username).cloned();
                match user {
                    Some(u) if u.password == password => {
                        Ok(LoginAnswer::Session(self.mint(&u.principal, u.name, None, None, Vec::new())))
                    }
                    _ => Err(AuthFailure::new("wrong username or password")),
                }
            }
            LoginFlow::Session { ttl_secs, ceiling } => {
                let ctx = caller.ok_or_else(|| AuthFailure::new("a session needs a connection that is someone"))?;
                let principal = ctx.principal().ok_or_else(|| AuthFailure::new("a session needs a connection that is someone"))?;
                let mut layers = layers_of(ctx)?;
                if let Some(entries) = ceiling.filter(|c| !c.is_empty()) {
                    let parsed = Ceiling::parse(&entries).map_err(|e| AuthFailure::new(e.to_string()))?;
                    layers.push(parsed.text());
                }
                // Never outlive the session it was asked on.
                let ttl = match ctx.metadata.get("expires_at").and_then(|v| v.as_i64()) {
                    Some(end) => {
                        let left = (end - now()).max(0) as u64;
                        Some(ttl_secs.unwrap_or(self.default_ttl).min(left))
                    }
                    None => ttl_secs,
                };
                let name = ctx.get_metadata_string("name");
                let agent = ctx.get_metadata_string("agent");
                Ok(LoginAnswer::Session(self.mint(&principal, name, agent, ttl, layers)))
            }
        }
    }

    async fn signup(&self, caller: Option<&AuthContext>, _via: Option<String>) -> Result<SignupAnswer, AuthFailure> {
        match caller.and_then(|c| c.principal()) {
            None => Err(AuthFailure::new("sign in first (auth.login): signup asks for access for who you are")),
            Some(_) => Err(AuthFailure::new("you already hold a role here")),
        }
    }

    async fn ask_access(&self, caller: &AuthContext, via: Option<String>) -> Result<Waiting, AuthFailure> {
        let principal = caller.principal().ok_or_else(|| AuthFailure::new("sign in first"))?;
        let text = principal.to_string();
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(w) = st.waiting.iter().find(|w| w.principal == text) {
            return Ok(w.clone());
        }
        let provider = via.or_else(|| text.split_once(':').map(|(k, _)| k.to_string()));
        let w = Waiting {
            principal: text,
            name: caller.get_metadata_string("name").or_else(|| caller.get_metadata_string("agent")),
            provider,
            since: now(),
        };
        st.waiting.push(w.clone());
        Ok(w)
    }

    fn waiting(&self) -> Vec<Waiting> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).waiting.clone()
    }

    async fn logout(&self, caller: &AuthContext) -> Result<(), AuthFailure> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.sessions.retain(|_, rec| rec.id != caller.session_id);
        Ok(())
    }
}

#[async_trait]
impl SessionValidator for MemoryAuthBackend {
    async fn validate(&self, credential: &str) -> Option<AuthContext> {
        self.context_of(Self::token_in(credential)?)
    }
}
