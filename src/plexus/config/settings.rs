//! NEST-21 · plexus-core's own settings: the transport, a mount's options,
//! the log's redactor. plexus-dyn declares its own beside them
//! (`dyn.repin_on_valid_cert`, `dyn.containment.*`, `dyn.require_consent`).

use super::{Config, Millis, Setting};

/// Plain `ws://` to a host beyond loopback (DYNAUTH-8's override, a test
/// network's). Read at every dial and mount. Critical: whoever flips it
/// lets a hop cross a network in clear.
pub const TRANSPORT_INSECURE_WS: Setting<bool> = crate::setting!(
    "transport.insecure_ws",
    default = false,
    reload = Live,
    sensitivity = Public,
    scope = Service,
    critical = true,
    doc = "plain ws:// to a peer beyond loopback (a test network's); read at every dial"
);

/// A PEM file of certificate authorities a `wss://` peer may chain to,
/// beside the webpki roots ([`ChildOptions::tls_roots`]). Not settable over
/// the wire: a CA added remotely could stand in for every peer.
///
/// [`ChildOptions::tls_roots`]: crate::plexus::ChildOptions::tls_roots
pub const TRANSPORT_TLS_ROOTS: Setting<Option<String>> = crate::setting!(
    "transport.tls_roots",
    default = None,
    reload = Live,
    remote = false,
    doc = "a PEM file of extra CAs a wss:// peer may chain to; read at every dial; the host's alone"
);

/// NEST-16's one-release escape: a child declaring no `needs` may call up
/// anything its caller could. Read at each mount. Critical: it widens what
/// every such child may call.
pub const CHILD_LEGACY_UPCALLS: Setting<bool> = crate::setting!(
    "child.legacy_upcalls",
    default = false,
    critical = true,
    doc = "a child declaring no needs calls up anything its caller could (NEST-11's rule); read at each mount"
);

/// A child's answer to `_info`, its schema, and each call's open.
pub const CHILD_TIMEOUT: Setting<Millis> = crate::setting!("child.timeout", default = Millis::secs(5), doc = "a child's answer to _info and each call's open; read at each mount");

/// Calls open on one child at once.
pub const CHILD_MAX_CALLS: Setting<usize> = crate::setting!("child.max_calls", default = 1024, doc = "calls open on one child at once; read at each mount");

/// Restarting (redialing) a child that died.
pub const CHILD_BACKOFF: Setting<Backoff> = crate::setting!("child.backoff", default = Backoff::DEFAULT, doc = "restarting a child that died: initial, max, per_minute; read at each mount");

/// Keys the log redacts beside the fixed credential keys (DYNAUTH-8's
/// redactor): process-wide, live.
pub const LOG_REDACT_KEYS: Setting<Vec<String>> = crate::setting!(
    "log.redact.keys",
    default = Vec::new(),
    scope = Process,
    doc = "keys whose values the log redacts, beside the fixed credential keys"
);

/// [`crate::plexus::Backoff`] as a setting holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Backoff {
    pub initial: Millis,
    pub max: Millis,
    pub per_minute: usize,
}

impl Backoff {
    /// 0.5 s → 30 s, at most 5 restarts a minute.
    pub const DEFAULT: Backoff = Backoff { initial: Millis::ms(500), max: Millis::secs(30), per_minute: 5 };
}

/// Declare plexus-core's settings in `c`, and keep the redactor's keys on
/// `log.redact.keys`.
pub(crate) fn declare_core(c: &Config) {
    c.declare(&TRANSPORT_INSECURE_WS);
    c.declare(&TRANSPORT_TLS_ROOTS);
    c.declare(&CHILD_LEGACY_UPCALLS);
    c.declare(&CHILD_TIMEOUT);
    c.declare(&CHILD_MAX_CALLS);
    c.declare(&CHILD_BACKOFF);
    c.declare(&LOG_REDACT_KEYS);
    // The first declaration of a process does not clear what another
    // service's store set: only a change does.
    let first = std::sync::atomic::AtomicBool::new(true);
    c.on_change(&LOG_REDACT_KEYS, move |keys| {
        if first.swap(false, std::sync::atomic::Ordering::SeqCst) && keys.is_empty() {
            return;
        }
        crate::plexus::redact::set_extra_keys(&keys);
    });
}

#[cfg(not(target_arch = "wasm32"))]
impl crate::plexus::ChildOptions {
    /// NEST-21: these options with every `child.*`, `transport.tls_roots`
    /// and (KEEL-7) `transport.insecure_ws` setting `c` holds above its default (a flag, the file, a runtime
    /// set) put over them. Read at each mount, so a change applies to the
    /// next one.
    pub fn configured(mut self, c: &Config) -> Self {
        use super::Source;
        if c.source(&CHILD_TIMEOUT) != Source::Default {
            self.timeout = c.get(&CHILD_TIMEOUT).0;
        }
        if c.source(&CHILD_MAX_CALLS) != Source::Default {
            self.max_calls = c.get(&CHILD_MAX_CALLS);
        }
        if c.source(&CHILD_BACKOFF) != Source::Default {
            let b = c.get(&CHILD_BACKOFF);
            self.backoff = crate::plexus::Backoff { initial: b.initial.0, max: b.max.0, per_minute: b.per_minute };
        }
        if c.source(&CHILD_LEGACY_UPCALLS) != Source::Default {
            self.legacy_upcalls = c.get(&CHILD_LEGACY_UPCALLS);
        }
        if c.source(&TRANSPORT_TLS_ROOTS) != Source::Default {
            self.tls_roots = c.get(&TRANSPORT_TLS_ROOTS).map(Into::into);
        }
        // KEEL-7: the override every dial reads, not plexus-dyn's alone.
        if c.source(&TRANSPORT_INSECURE_WS) != Source::Default {
            self.insecure_ws = c.get(&TRANSPORT_INSECURE_WS);
        }
        self
    }

    /// NEST-21: put what these options say above the defaults into `c` as
    /// the flag layer (what a host read from its flags at start), so
    /// `config.list` shows it and a runtime set goes over it.
    pub fn seed(&self, c: &Config) {
        use super::Source;
        let d = Self::default();
        if self.timeout != d.timeout {
            c.seed(&CHILD_TIMEOUT, Source::Flag, Some(Millis(self.timeout)));
        }
        if self.max_calls != d.max_calls {
            c.seed(&CHILD_MAX_CALLS, Source::Flag, Some(self.max_calls));
        }
        if (self.backoff.initial, self.backoff.max, self.backoff.per_minute) != (d.backoff.initial, d.backoff.max, d.backoff.per_minute) {
            c.seed(&CHILD_BACKOFF, Source::Flag, Some(Backoff { initial: Millis(self.backoff.initial), max: Millis(self.backoff.max), per_minute: self.backoff.per_minute }));
        }
        if self.legacy_upcalls != d.legacy_upcalls {
            c.seed(&CHILD_LEGACY_UPCALLS, Source::Flag, Some(self.legacy_upcalls));
        }
        if let Some(r) = &self.tls_roots {
            c.seed(&TRANSPORT_TLS_ROOTS, Source::Flag, Some(Some(r.display().to_string())));
        }
        if self.insecure_ws != d.insecure_ws {
            c.seed(&TRANSPORT_INSECURE_WS, Source::Flag, Some(self.insecure_ws));
        }
    }
}
