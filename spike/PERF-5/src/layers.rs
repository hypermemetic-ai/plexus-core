//! A sampled stack → the layer it is charged to. Two views:
//!
//! - **layer** — the five layers of the ticket (jsonrpsee · serde_json ·
//!   gate · tokio · socket) plus plexus-core's dispatch (the macro's code,
//!   `Box<dyn Stream>`, the item's wrapping): the innermost frame that
//!   names one wins, so an allocation made by serde_json is serde_json's.
//!   A syscall is `socket` (send/recv/read/write) or `tokio` (epoll, futex —
//!   the reactor and the wakeups).
//! - **leaf** — what the CPU was doing at the sample: alloc, memcpy, a
//!   syscall, or code.
//!
//! The samples are SIGPROF (CPU time, user + kernel, by the process's own
//! timer): a sample inside a syscall lands on its libc wrapper — the kernel's
//! frames are not seen (perf_event_paranoid 2), but its time is.

use std::collections::BTreeMap;

pub const LAYERS: &[&str] = &["socket", "jsonrpsee", "serde_json", "plexus", "gate", "tokio", "alloc-free", "other"];

fn any(f: &str, keys: &[&str]) -> bool {
    keys.iter().any(|k| f.contains(k))
}

/// A syscall a sample stands in: the frame just above glibc's
/// `__syscall_cancel` (or the leaf itself), by its bare name.
fn syscall_of(frames: &[&str]) -> Option<&'static str> {
    let n = frames.len();
    for i in (n.saturating_sub(4)..n).rev() {
        let head = frames[i].split('<').next().unwrap_or("");
        let socket_ctx = frames[..i].iter().rev().take(4).any(|f| any(f, &["net::", "Socket", "TcpStream", "socket"]));
        match head {
            "send" | "__send" | "sendto" | "sendmsg" | "__libc_sendmsg" | "__libc_send" | "recv" | "__libc_recv" | "recvfrom" | "recvmsg" | "writev" => return Some("socket"),
            "write" | "__libc_write" | "read" | "__libc_read" if socket_ctx => return Some("socket"),
            "write" | "__libc_write" | "read" | "__libc_read" => return Some("park"),
            "epoll_wait" | "epoll_ctl" | "syscall" | "futex_wait" | "futex_wake" | "sched_yield" | "__futex_abstimed_wait_common" => return Some("park"),
            _ => {}
        }
    }
    None
}

const ALLOC: &[&str] = &["malloc", "_int_free", "cfree", "__libc_free", "realloc", "calloc", "perf5::alloc::", "__rust_alloc", "__rust_dealloc", "__rust_realloc", "tcache", "unlink_chunk", "drop_in_place"];
const MEMCPY: &[&str] = &["memmove", "memcpy", "memset"];

/// The crate a frame belongs to: its own name if it says one, else the
/// first crate path in its generics that is not std's.
fn crate_of(f: &str) -> Option<&'static str> {
    let head = f.split('<').next().unwrap_or(f);
    let named = |h: &str| -> Option<&'static str> {
        if any(h, &["plexus_auth_core", "grant_gate", "scope_gate", "duplex_gate"]) || matches!(h, "decide" | "check" | "standing" | "alive" | "caller_of" | "chain" | "held") {
            return Some("gate");
        }
        if any(h, &["serde_json", "serde::", "ryu::", "itoa::", "to_raw_value", "to_value", "format_escaped_str", "visit_map", "from_slice", "from_trait", "deserialize", "serialize", "to_vec", "to_string", "to_writer", "end_map", "serialize_field", "serialize_str", "serialize_map"]) {
            return Some("serde_json");
        }
        if any(h, &["plexus_core", "plexus_macros", "plexus_client", "perf5::echo", "async_stream", "pipe_stream_to_subscription", "route_with_ctx", "route_ungated", "wrap_stream", "assemble_envelope", "serialize_with_credential_capture", "StreamMetadata", "PlexusStreamItem", "BenchActivation", "dispatch"]) {
            return Some("plexus");
        }
        if any(h, &["jsonrpsee", "soketto", "hyper", "tower", "plexus_transport", "sub_message_to_json", "send_task", "background_task", "http::"]) {
            return Some("jsonrpsee");
        }
        if any(h, &["tokio::", "mio::"]) {
            return Some("tokio");
        }
        None
    };
    if let Some(c) = named(head) {
        return Some(c);
    }
    // the first non-std crate path in the generics
    let gen = &f[head.len()..];
    let mut best: Option<(usize, &'static str)> = None;
    for (key, layer) in [
        ("plexus_auth_core::", "gate"),
        ("serde_json::", "serde_json"),
        ("plexus_core::", "plexus"),
        ("perf5::", "plexus"),
        ("async_stream::", "plexus"),
        ("jsonrpsee", "jsonrpsee"),
        ("soketto::", "jsonrpsee"),
        ("hyper", "jsonrpsee"),
        ("tower", "jsonrpsee"),
        ("plexus_transport::", "jsonrpsee"),
        ("tokio::", "tokio"),
        ("mio::", "tokio"),
    ] {
        if let Some(i) = gen.find(key) {
            if best.map_or(true, |(j, _)| i < j) {
                best = Some((i, layer));
            }
        }
    }
    best.map(|(_, l)| l)
}

/// (layer, leaf) of a stack, root first.
pub fn classify(stack_root_first: &[&str]) -> (&'static str, &'static str) {
    if let Some(sc) = syscall_of(stack_root_first) {
        return if sc == "socket" { ("socket", "syscall:socket") } else { ("tokio", "syscall:park") };
    }
    let mut leaf = "code";
    for f in stack_root_first.iter().rev().take(4) {
        let head = f.split('<').next().unwrap_or(f);
        if any(head, ALLOC) || head.starts_with("_int_") {
            leaf = "alloc";
            break;
        }
        if any(head, MEMCPY) {
            leaf = "memcpy";
            break;
        }
    }
    for f in stack_root_first.iter().rev() {
        if let Some(l) = crate_of(f) {
            return (l, leaf);
        }
    }
    if leaf == "alloc" {
        return ("alloc-free", leaf);
    }
    ("other", leaf)
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Shares {
    pub samples: u64,
    pub by_layer: BTreeMap<String, u64>,
    pub by_leaf: BTreeMap<String, u64>,
}

impl Shares {
    pub fn pct(&self) -> BTreeMap<String, f64> {
        self.by_layer.iter().map(|(k, v)| (k.clone(), 100.0 * *v as f64 / self.samples.max(1) as f64)).collect()
    }
    pub fn leaf_pct(&self) -> BTreeMap<String, f64> {
        self.by_leaf.iter().map(|(k, v)| (k.clone(), 100.0 * *v as f64 / self.samples.max(1) as f64)).collect()
    }
}

/// Folded stacks (`a;b;c N`, root first) → shares. Lines whose stack
/// matches `skip` (e.g. the client's threads) are left out.
pub fn shares(folded: &str, keep: impl Fn(&str) -> bool) -> Shares {
    let mut s = Shares::default();
    for line in folded.lines() {
        let Some((stack, n)) = line.rsplit_once(' ') else { continue };
        let Ok(n) = n.trim().parse::<u64>() else { continue };
        if !keep(stack) {
            continue;
        }
        let frames: Vec<&str> = stack.split(';').collect();
        let (layer, leaf) = classify(&frames);
        s.samples += n;
        *s.by_layer.entry(layer.to_string()).or_default() += n;
        *s.by_leaf.entry(leaf.to_string()).or_default() += n;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allocation_is_charged_to_the_layer_that_made_it() {
        let st = ["tokio::runtime::task::harness", "poll<jsonrpsee_server::x>", "pipe_stream_to_subscription", "to_raw_value<plexus_core::plexus::types::PlexusStreamItem>", "insert<alloc::string::String, serde_json::value::Value, alloc::alloc::Global>", "finish_grow", "_int_malloc"];
        assert_eq!(classify(&st), ("serde_json", "alloc"));
    }

    #[test]
    fn a_send_is_the_socket_whoever_called_it() {
        let st = ["tokio::runtime", "poll<jsonrpsee_server::transport::ws::send_task>", "<std::sys::net::connection::socket::TcpStream>::write", "send", "__syscall_cancel"];
        assert_eq!(classify(&st), ("socket", "syscall:socket"));
    }

    #[test]
    fn epoll_and_futex_are_tokios() {
        assert_eq!(classify(&["tokio::runtime::scheduler", "poll", "select", "epoll_wait", "__syscall_cancel"]).0, "tokio");
        assert_eq!(classify(&["park_internal", "<std::sys::fs::unix::File>::write", "<std::sys::fd::unix::FileDesc>::write", "write", "__syscall_cancel"]).0, "tokio", "an eventfd wake");
        assert_eq!(classify(&["tokio::runtime::park", "futex_wait", "syscall"]).0, "tokio");
    }

    #[test]
    fn the_gate_wins_over_plexus_core_that_called_it() {
        let st = ["tokio::x", "{async_block#0}<(), plexus_core::plexus::plexus::x>", "decide", "check", "from_iter<plexus_auth_core::grants::ScopeRef, core::iter::Map>", "hashbrown::map::x"];
        assert_eq!(classify(&st).0, "gate");
    }
}
