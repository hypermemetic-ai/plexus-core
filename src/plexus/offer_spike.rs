//! LOCAL-3 (spike, never merged): a whole service offered on a connection
//! it dialed — the callee's side of a symmetric connection, decided by the
//! **callee's own gate**.
//!
//! A call that arrives on the connection is routed through the service's
//! [`DynamicHub::route_with_ctx`] — the same gate, roles and routing as a
//! call from any client — as **the peer**: the principal the dialer pinned
//! (or that the peer proved) for the address it dialed, never a principal
//! the frame claims. The frame's `hop.for` names whom the peer acts for:
//! BIDIR-7's `hop_identity` (the hop is the principal, the caller named
//! `for`, the verdict `*` — a call into a client: its scopes are its own).
//! A dialer with no identity for its peer serves it as anonymous.

use std::sync::Arc;

use futures::stream::{BoxStream, StreamExt};
use plexus_client::offer::{Offered, ServedCall};
use serde_json::{json, Value};

use super::auth::AuthContext;
use super::in_process::to_client_item;
use super::plexus::{error_item, DynamicHub};

/// A [`DynamicHub`] offered on a connection, for one peer.
#[derive(Clone)]
pub struct ServiceOffer {
    hub: Arc<DynamicHub>,
    activations: Vec<String>,
    peer: Option<AuthContext>,
}

impl std::fmt::Debug for ServiceOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceOffer").field("activations", &self.activations).finish()
    }
}

impl ServiceOffer {
    /// Offer `activations` of `hub`; calls into them run as `peer` (`None`:
    /// anonymous).
    pub fn new(hub: Arc<DynamicHub>, activations: &[&str], peer: Option<AuthContext>) -> Self {
        Self { hub, activations: activations.iter().map(|s| s.to_string()).collect(), peer }
    }

    /// The context a call runs under: the peer, for whom the frame names.
    pub fn context(&self, for_: &[String]) -> Option<AuthContext> {
        let peer = self.peer.as_ref()?;
        let Some((first, rest)) = for_.split_first() else {
            return Some(peer.clone());
        };
        let meta = json!({ plexus_auth_core::duplex::FOR_KEY: rest });
        let caller = match first.parse() {
            Ok(p) => AuthContext::for_principal(&p, "", vec![], meta),
            Err(_) => AuthContext::new(first.clone(), String::new(), vec![], meta),
        };
        Some(plexus_auth_core::duplex::hop_identity(peer, &caller, &[plexus_auth_core::grants::ScopeRef::Everywhere]))
    }
}

impl Offered for ServiceOffer {
    fn namespace(&self) -> &str {
        self.hub.runtime_namespace()
    }

    fn activations(&self) -> Vec<String> {
        self.activations.clone()
    }

    fn schema(&self) -> Value {
        let schema = super::plexus::Activation::plugin_schema(&*self.hub);
        let mut v = serde_json::to_value(&schema).unwrap_or(Value::Null);
        // Only what is offered.
        if let Some(children) = v.get_mut("children").and_then(Value::as_array_mut) {
            children.retain(|c| c.get("namespace").and_then(Value::as_str).is_some_and(|n| self.activations.iter().any(|a| a == n)));
        }
        v
    }

    fn serve(&self, call: ServedCall) -> BoxStream<'static, Value> {
        let hub = self.hub.clone();
        let for_ = call.hop.as_ref().map(|h| h.for_.clone()).unwrap_or_default();
        let ctx = self.context(&for_);
        let ns = hub.runtime_namespace().to_string();
        futures::stream::once(async move {
            match hub.route_with_ctx(&call.method, call.params, ctx.as_ref(), None).await {
                Ok(stream) => stream
                    .map(|item| serde_json::to_value(to_client_item(item)).unwrap_or(Value::Null))
                    .left_stream(),
                Err(e) => futures::stream::once(async move { error_item(&ns, &e) }).right_stream(),
            }
        })
        .flatten()
        .boxed()
    }
}
