//! A test of a Plexus service starts from a **world**: a **host** — a
//! service with its gate, the roles its activations declare and any the test
//! adds — and **callers** by name, each holding the role of its name.
//!
//! ```
//! use futures::stream::Stream;
//! use plexus_testkit::{Forbidden, Unauthenticated, World, NOBODY, VIEWER};
//! use serde_json::json;
//!
//! #[derive(Clone)]
//! struct ShopActivation;
//!
//! /// A shop.
//! #[plexus_macros::activation(namespace = "shop", roles(viewer = ["items"]))]
//! impl ShopActivation {
//!     /// What is on the shelves.
//!     #[plexus_macros::method]
//!     async fn items(&self) -> impl Stream<Item = String> + Send + 'static {
//!         futures::stream::iter(["flour".to_string()])
//!     }
//!     /// The till: no role the shop declares lists it.
//!     #[plexus_macros::method]
//!     async fn till(&self) -> impl Stream<Item = u64> + Send + 'static {
//!         futures::stream::iter([42])
//!     }
//! }
//!
//! const CLERK: &str = "key:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let world = World::new();
//! let host = world.host().with(ShopActivation).role("clerk", ["shop.till"]).member(CLERK, "clerk").await;
//!
//! assert_eq!(host.as_(VIEWER).call("shop.items", json!({})).await.answers(1), [json!("flour")]);
//! assert_eq!(host.as_(CLERK).call("shop.till", json!({})).await.answer::<u64>(), 42);
//! host.as_(VIEWER).call("shop.till", json!({})).await.refused(Forbidden).naming("shop.till").listed_by(["clerk", "admin"]);
//! host.as_(NOBODY).call("shop.items", json!({})).await.refused(Forbidden).naming("shop.items");
//! host.anonymous().call("shop.items", json!({})).await.refused(Unauthenticated);
//! # }
//! ```
//!
//! A call's [`Outcome`] is what it did, in the domain's words: it
//! **answered** ([`answers`](Outcome::answers), [`answer`](Outcome::answer),
//! [`items`](Outcome::items)), it was **refused** — by the gate or router
//! before it opened ([`refused`](Outcome::refused)), or in band by a child
//! past it ([`refused_in_band`](Outcome::refused_in_band)) — or it
//! **failed** ([`failed`](Outcome::failed)). A failed assertion says the
//! method, the caller and the whole outcome. [`Outcome::raw`] has every
//! item as a value; [`Caller::stream`] is the call's stream itself.
//!
//! The parts a host is made of — [`parts::Members`], [`parts::Everywhere`],
//! [`parts::Shortcodes`], [`parts::who`] (each caller in a session of its
//! own, [`parts::session_of`]), [`parts::items`] (or
//! [`parts::every_item`], the closing `done` kept) — are public for
//! a test that builds something the host does not (a second gate, a
//! transport as a caller).
//!
//! This is the kit's root (KEEL-9); there is no `#[plexus_test]` attribute
//! yet: a test makes its world with [`World::new`], which works the same in
//! a `#[tokio::test]` and in a `harness = false` binary's `fn main`.

use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use plexus_core::plexus::{
    Activation, AuthContext, AuthSetup, ChildRouter, Gate, MemoryAuthBackend, MemoryRoles, PlexusStream, Resolve, RoleTable,
    Roles,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::Value;

pub mod outcome;
pub mod parts;

pub use outcome::RefusalKind::{Forbidden, InvalidParams, NotFound, Unauthenticated};
pub use outcome::{Failure, Outcome, Refusal, RefusalKind};
use parts::{Everywhere, Members};

/// The viewer: holds the role `viewer` everywhere.
pub const VIEWER: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The editor: holds the role `editor` everywhere.
pub const EDITOR: &str = "key:edededededededededededededededededededededededededededededededed";
/// The admin: holds `admin` everywhere, which holds every grant.
pub const ADMIN: &str = "key:adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad";
/// The user: holds the role `user` everywhere (a role no activation
/// declares unless the test gives it grants).
pub const USER: &str = "key:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// A signed-in caller who holds nothing.
pub const NOBODY: &str = "key:0000000000000000000000000000000000000000000000000000000000000000";

/// Each named caller and the role it holds in every host.
const NAMED: [(&str, &str); 4] = [(VIEWER, "viewer"), (EDITOR, "editor"), (ADMIN, "admin"), (USER, "user")];
/// Each named caller by its name, for a failure's message.
const NAMES: [(&str, &str); 5] = [(VIEWER, "VIEWER"), (EDITOR, "EDITOR"), (ADMIN, "ADMIN"), (USER, "USER"), (NOBODY, "NOBODY")];

/// Where a test's services live. One per test; every host is made from it.
#[derive(Clone, Default)]
pub struct World {
    _kept: Arc<()>,
}

impl World {
    /// A new, empty world.
    pub fn new() -> Self {
        Self::default()
    }

    /// A host to build: the service `host`, gated, its callers by name.
    /// Awaiting it builds it.
    pub fn host(&self) -> HostBuilder {
        HostBuilder {
            world: self.clone(),
            name: "host".into(),
            steps: Vec::new(),
            roles: Vec::new(),
            members: Vec::new(),
            named: true,
            through: None,
            auth: false,
            resolve: Arc::new(Everywhere),
        }
    }
}

type Step = Box<dyn FnOnce(DynamicHub) -> DynamicHub + Send>;
type Through = Box<dyn FnOnce(Arc<dyn Roles>) -> Arc<dyn Roles> + Send>;

/// A host being described: what it serves, the roles beyond the declared,
/// who holds what. `.await` it for the [`Host`].
#[must_use = "a host is built by awaiting it"]
pub struct HostBuilder {
    world: World,
    name: String,
    steps: Vec<Step>,
    roles: Vec<(String, Vec<String>)>,
    members: Vec<(String, String, String)>,
    named: bool,
    through: Option<Through>,
    auth: bool,
    resolve: Arc<dyn Resolve>,
}

impl HostBuilder {
    /// The service's name (its namespace: `<name>.schema`, `<name>.hash`);
    /// `host` unless said.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Serve `activation` (an activation, or a mounted child), in the order
    /// given.
    pub fn with<A: Activation + ChildRouter + Clone + 'static>(mut self, activation: A) -> Self {
        self.steps.push(Box::new(move |s| s.register(activation)));
        self
    }

    /// Anything else the service is built with, in order with
    /// [`with`](Self::with): `configure(|s| s.with_config_service())`.
    pub fn configure(mut self, f: impl FnOnce(DynamicHub) -> DynamicHub + Send + 'static) -> Self {
        self.steps.push(Box::new(f));
        self
    }

    /// The role `name` holds `grants` too, beside what the activations
    /// declare for it.
    pub fn role<G: IntoIterator>(mut self, name: &str, grants: G) -> Self
    where
        G::Item: AsRef<str>,
    {
        self.roles.push((name.to_string(), grants.into_iter().map(|g| g.as_ref().to_string()).collect()));
        self
    }

    /// [`role`](Self::role), for each `(name, grants)`.
    pub fn roles<'a, I, G>(self, roles: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, G)>,
        G: IntoIterator,
        G::Item: AsRef<str>,
    {
        roles.into_iter().fold(self, |b, (name, grants)| b.role(name, grants))
    }

    /// `who` holds `role` everywhere — a caller the test names itself, or a
    /// named one given another role besides its own.
    pub fn member(self, who: &str, role: &str) -> Self {
        self.member_at(who, role, "*")
    }

    /// `who` holds `role` on `scope` alone — `*`, or a scope's name
    /// (`MENGER`), which [`resolving`](Self::resolving) says what lives in.
    pub fn member_at(mut self, who: &str, role: &str, scope: &str) -> Self {
        self.members.push((who.to_string(), role.to_string(), scope.to_string()));
        self
    }

    /// No caller holds anything unless the test says so: the named callers
    /// ([`VIEWER`], [`EDITOR`], [`ADMIN`], [`USER`]) are not seated — for a
    /// test whose own principals share their keys, or that counts who holds
    /// what.
    pub fn without_named_callers(mut self) -> Self {
        self.named = false;
        self
    }

    /// Where a target lives, the gate asks `resolve` — [`parts::Shortcodes`],
    /// or the test's own; [`parts::Everywhere`] unless said.
    pub fn resolving(mut self, resolve: impl Resolve + 'static) -> Self {
        self.resolve = Arc::new(resolve);
        self
    }

    /// The gate reads the roles through `f` — for a service that adds to a
    /// role while it serves (plexus-dyn's consent). Not with
    /// [`with_auth`](Self::with_auth), whose roles are its own store.
    pub fn roles_through(mut self, f: impl FnOnce(Arc<dyn Roles>) -> Arc<dyn Roles> + Send + 'static) -> Self {
        self.through = Some(Box::new(f));
        self
    }

    /// Turn login on, as a service does: the `auth` activation mounted
    /// (`auth.requires`, `auth.roles`, `auth.whoami`, …) and the gate built
    /// from its stores, the roles editable.
    pub fn with_auth(mut self) -> Self {
        self.auth = true;
        self
    }

    fn build(self) -> Host {
        let mut service = DynamicHub::new(self.name);
        for step in self.steps {
            service = step(service);
        }
        let members = Arc::new(Members::default());
        if self.named {
            for (who, role) in NAMED {
                members.hold(who, role);
            }
        }
        for (who, role, scope) in &self.members {
            members.hold_at(who, role, scope);
        }
        let service = if self.auth {
            assert!(self.through.is_none(), "roles_through is not for a host with_auth: its roles are the auth store's");
            let roles = Arc::new(MemoryRoles::default());
            let backend = Arc::new(MemoryAuthBackend::new("http://x/login"));
            let service = service.with_auth(AuthSetup::new(backend, roles.clone(), members.clone(), self.resolve));
            roles.seed(&merged(service.declared_roles(), self.roles));
            service
        } else {
            let lists = merged(service.declared_roles(), self.roles);
            let table: Arc<dyn Roles> = Arc::new(RoleTable::from_lists(lists.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str)))));
            let roles = match self.through {
                Some(f) => f(table),
                None => table,
            };
            service.with_gate(Arc::new(Gate::new(members.clone(), roles, self.resolve)))
        };
        Host { _world: self.world, service: Arc::new(service), members, named: self.named }
    }
}

/// The declared roles, each with the test's grants added.
fn merged(
    mut declared: std::collections::BTreeMap<String, Vec<String>>,
    extra: Vec<(String, Vec<String>)>,
) -> std::collections::BTreeMap<String, Vec<String>> {
    for (role, grants) in extra {
        let held = declared.entry(role).or_default();
        for g in grants {
            if !held.contains(&g) {
                held.push(g);
            }
        }
    }
    declared
}

impl IntoFuture for HostBuilder {
    type Output = Host;
    type IntoFuture = Pin<Box<dyn Future<Output = Host> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.build() })
    }
}

/// A gated service in the world, built in process: every scope resolves,
/// each named caller holds its role.
#[derive(Clone)]
pub struct Host {
    _world: World,
    service: Arc<DynamicHub>,
    members: Arc<Members>,
    named: bool,
}

impl Host {
    /// The caller `who` (a principal: [`VIEWER`], or one the test names).
    pub fn as_(&self, who: &str) -> Caller {
        let caller = Caller::new(self.service.clone(), Some(parts::who(who)));
        // A named caller by its name — only where the named callers are
        // seated: elsewhere a test's principal may share its key.
        match NAMES.iter().find(|(p, _)| *p == who) {
            Some((_, name)) if self.named => Caller { name: name.to_string(), ..caller },
            _ => caller,
        }
    }

    /// A caller who has not signed in.
    pub fn anonymous(&self) -> Caller {
        Caller::new(self.service.clone(), None)
    }

    /// The service itself, for what the kit does not say yet (its root, its
    /// schema, a transport over it).
    pub fn service(&self) -> &Arc<DynamicHub> {
        &self.service
    }

    /// The gate every call goes through.
    pub fn gate(&self) -> &Arc<Gate> {
        self.service.gate().expect("a host is gated")
    }

    /// Who holds which role: editable while the host serves (then say so
    /// to the [`gate`](Self::gate), `moved`).
    pub fn members(&self) -> &Arc<Members> {
        &self.members
    }
}

/// Someone calling a service: a principal, or no one signed in.
#[derive(Clone)]
pub struct Caller {
    service: Arc<DynamicHub>,
    auth: Option<AuthContext>,
    name: String,
}

impl Caller {
    /// `auth` calling `service` — for a service the kit did not build (one
    /// with no gate) or a context it does not make (a session with a
    /// ceiling); a host's callers are [`Host::as_`] and [`Host::anonymous`].
    pub fn new(service: impl Into<Arc<DynamicHub>>, auth: Option<AuthContext>) -> Self {
        let name = auth.as_ref().map_or_else(|| "anonymous".to_string(), |a| a.user_id.clone());
        Self { service: service.into(), auth, name }
    }

    /// Call `method` with `params` through the service's gate, and read
    /// the whole of what it did: an [`Outcome`].
    pub async fn call(&self, method: &str, params: Value) -> Outcome {
        let opened = match self.stream(method, params).await {
            Ok(stream) => Ok(stream.collect().await),
            Err(e) => Err(e),
        };
        Outcome::new(method, self.name.clone(), opened)
    }

    /// The call's stream itself, as the service opens it — for a test that
    /// reads it as it comes (a watch, a change mid-stream) — or why it was
    /// not opened. [`Outcome::of`] reads what is left of it.
    pub async fn stream(&self, method: &str, params: Value) -> Result<PlexusStream, PlexusError> {
        self.service.route(method, params, self.auth.as_ref()).await
    }
}
