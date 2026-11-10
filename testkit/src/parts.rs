//! What a [`Host`](crate::Host) is made of, for a test that builds
//! something the host does not: who holds what ([`Members`]), where every
//! target lives ([`Everywhere`], or by its shortcode: [`Shortcodes`]), a
//! caller's context ([`who`]) and a call's answer as values ([`items`]).

use std::sync::Mutex;

use futures::StreamExt;
use plexus_auth_core::identity::Principal;
use plexus_auth_core::RoleName;
use plexus_core::plexus::{
    AuthContext, Membership, MembershipStore, Memberships, PlexusStream, PlexusStreamItem, Resolve, ScopeRef, StoreError,
};
use plexus_core::PlexusError;
use serde_json::{json, Value};

/// Who holds which role where: a list, editable while a service serves.
#[derive(Default)]
pub struct Members(pub Mutex<Vec<Membership>>);

impl Members {
    /// `who` holds `role` everywhere.
    pub fn hold(&self, who: &str, role: &str) {
        self.hold_at(who, role, "*");
    }

    /// `who` holds `role` on `scope` — `*`, or a scope's name (`MENGER`).
    pub fn hold_at(&self, who: &str, role: &str, scope: &str) {
        let principal = who.parse().unwrap_or_else(|e| panic!("{who}: not a principal: {e:?}"));
        self.0.lock().unwrap().push(Membership { principal, role: RoleName::new(role), scope: ScopeRef::parse(scope) });
    }

    /// `who` holds nothing any more, anywhere. (Say so to the gate if a
    /// test needs it to notice: `moved`.)
    pub fn forget(&self, who: &str) {
        let principal: Principal = who.parse().unwrap_or_else(|e| panic!("{who}: not a principal: {e:?}"));
        self.0.lock().unwrap().retain(|m| m.principal != principal);
    }
}

impl Memberships for Members {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// As the `auth` activation's store (`auth.grant`, `auth.revoke`).
#[async_trait::async_trait]
impl MembershipStore for Members {
    async fn grant(&self, membership: Membership) -> Result<(), StoreError> {
        let mut rows = self.0.lock().unwrap();
        if !rows.contains(&membership) {
            rows.push(membership);
        }
        Ok(())
    }

    async fn revoke(&self, principal: &Principal, role: Option<&RoleName>, scope: &ScopeRef) -> Result<Vec<RoleName>, StoreError> {
        let mut rows = self.0.lock().unwrap();
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

/// Every target lives everywhere (`*`): a membership on `*` reaches it.
pub struct Everywhere;

impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

/// A ticket lives in its shortcode: `CODE-n` → `[CODE, *]`, a bare `CODE`
/// → `[CODE, *]`; a target that is no shortcode (empty, or not all
/// upper-case letters) locates nothing, and the call is refused.
pub struct Shortcodes;

impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return None;
        }
        Some(vec![ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

/// The context of a call made by the principal `p` (session `s1`).
pub fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], Value::Null)
}

/// A session id planted in [`who_carrying_secrets`]'s context: a test
/// checks it never crosses to a child or a peer.
pub const SESSION_SECRET: &str = "mgs_SESSIONSECRET0123456789";
/// A key proof planted in [`who_carrying_secrets`]'s context.
pub const KEY_SECRET: &str = "plexus-key.PROOFSECRET0123456789";

/// The context of a call by `p` that carries a session id and a key proof
/// ([`SESSION_SECRET`], [`KEY_SECRET`]) — what must never reach a child.
pub fn who_carrying_secrets(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), SESSION_SECRET, vec![], json!({ "session_key": KEY_SECRET, "token": KEY_SECRET }))
}

/// A call's answer as values: each data item's content, any other item as
/// the wire writes it (`{"type": "error", …}`), the closing `done` left
/// out; a call not routed is one item, `{"route_error": "<the error, Debug>"}`
/// — Debug, so a refusal names its grant, scope and the roles that list it.
pub async fn items(routed: Result<PlexusStream, PlexusError>) -> Vec<Value> {
    match routed {
        Err(e) => vec![json!({ "route_error": format!("{e:?}") })],
        Ok(stream) => stream
            .map(|i| match i {
                PlexusStreamItem::Data { content, .. } => content.into_value(),
                other => serde_json::to_value(other).unwrap(),
            })
            .filter(|v| futures::future::ready(v["type"] != "done"))
            .collect()
            .await,
    }
}
