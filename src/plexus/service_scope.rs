//! NEST-11 · which service a call is routed in.
//!
//! A call enters a service at [`DynamicHub::route_with_ctx`] (a socket's
//! `{ns}.call`, a [`HubTransport`](super::HubTransport), a test's `route`);
//! the outermost one it enters is its service, and everything that routing
//! reaches — an activation, a child mounted below it, a peer in a slot —
//! runs knowing it. A [`RemoteChild`](super::RemoteChild) keeps it, weakly,
//! for each call it forwards: the far side's calls back under that call are
//! routed through this service's own routing and gate, as its caller.
//!
//! Nothing here admits anyone: the service is a route, never a caller.

use std::future::Future;
use std::sync::Weak;

use super::plexus::DynamicHub;

tokio::task_local! {
    static SERVICE: WeakService;
}

/// A service, held weakly: what a child keeps of the service it is mounted
/// in, so it never keeps that service alive. Cheap to clone.
#[derive(Clone)]
pub struct WeakService(Weak<super::plexus::DynamicHubInner>);

impl std::fmt::Debug for WeakService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.upgrade() {
            Some(s) => write!(f, "WeakService({})", s.runtime_namespace()),
            None => f.write_str("WeakService(gone)"),
        }
    }
}

impl WeakService {
    pub(crate) fn new(inner: Weak<super::plexus::DynamicHubInner>) -> Self {
        Self(inner)
    }

    /// KEEL-54: whether this is `hub`'s handle.
    pub(crate) fn is(&self, hub: &DynamicHub) -> bool {
        hub.is_inner(&self.0)
    }

    /// The service, while it lives.
    pub fn upgrade(&self) -> Option<DynamicHub> {
        self.0.upgrade().map(DynamicHub::from_inner)
    }
}

/// Whether the running task is routing a call in some service already.
pub(crate) fn entered() -> bool {
    SERVICE.try_with(|_| ()).is_ok()
}

/// The service the running call was routed in, if any.
pub(crate) fn current() -> Option<WeakService> {
    SERVICE.try_with(WeakService::clone).ok()
}

/// Run `fut` routed in `service`.
pub(crate) fn scope<F: Future>(service: WeakService, fut: F) -> impl Future<Output = F::Output> {
    SERVICE.scope(service, fut)
}
