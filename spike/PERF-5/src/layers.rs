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

const SOCKET: &[&str] = &[
    "__send", "sendmsg", "sendto", "__libc_send", "writev", "__libc_write", "__GI___libc_write", "__write", "__libc_recv", "recvfrom",
    "recvmsg", "__GI___libc_read", "__libc_read", "__read", "std::sys::net", "mio::net", "mio::io_source", "tokio::net::tcp::stream",
    "<tokio::net::tcp::stream::TcpStream as tokio::io::async_write::AsyncWrite>", "<tokio::net::tcp::stream::TcpStream as tokio::io::async_read::AsyncRead>",
];
const PARK: &[&str] = &["epoll_wait", "epoll_ctl", "futex", "syscall", "mio::poll", "Selector::select", "parking_lot", "std::sys::pal::unix::futex", "sched_yield"];
const ALLOC: &[&str] = &["malloc", "_int_free", "cfree", "__libc_free", "realloc", "_int_realloc", "calloc", "perf5::alloc::", "__rust_alloc", "__rust_dealloc", "__rust_realloc"];
const MEMCPY: &[&str] = &["memmove", "memcpy", "__memset", "memset"];

/// The layer of one frame, if it names one.
fn layer_of(f: &str) -> Option<&'static str> {
    if any(f, &["plexus_auth_core", "grant_gate", "scope_gate", "duplex_gate"]) {
        return Some("gate");
    }
    if any(f, &["serde_json", "serde::", "<serde", "ryu::", "itoa::", "sonic_rs", "simd_json"]) {
        return Some("serde_json");
    }
    if any(f, &["plexus_core", "plexus_macros", "perf5::echo", "async_stream", "plexus_client"]) {
        return Some("plexus");
    }
    if any(f, &["jsonrpsee", "soketto", "hyper::", "hyper_util", "plexus_transport", "tower::", "<tower"]) {
        return Some("jsonrpsee");
    }
    if any(f, &["tokio::", "<tokio", "mio::"]) {
        return Some("tokio");
    }
    None
}

/// (layer, leaf) of a stack, root first.
pub fn classify(stack_root_first: &[&str]) -> (&'static str, &'static str) {
    let leaf_frame = stack_root_first.last().copied().unwrap_or("");
    let mut leaf = "code";
    // the leaf view: the innermost frames decide
    for f in stack_root_first.iter().rev().take(6) {
        if any(f, ALLOC) {
            leaf = "alloc";
            break;
        }
        if any(f, MEMCPY) {
            leaf = "memcpy";
            break;
        }
        if any(f, SOCKET) {
            leaf = "syscall:socket";
            break;
        }
        if any(f, PARK) {
            leaf = "syscall:park";
            break;
        }
    }
    let _ = leaf_frame;
    if leaf == "syscall:socket" {
        return ("socket", leaf);
    }
    if leaf == "syscall:park" {
        return ("tokio", leaf);
    }
    for f in stack_root_first.iter().rev() {
        if let Some(l) = layer_of(f) {
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
        let st = ["tokio::runtime::task::harness", "jsonrpsee_server::x", "plexus_core::plexus::plexus::pipe_stream_to_subscription", "serde_json::value::to_raw_value", "alloc::raw_vec::finish_grow", "malloc"];
        assert_eq!(classify(&st), ("serde_json", "alloc"));
    }

    #[test]
    fn a_send_is_the_socket_whoever_called_it() {
        let st = ["tokio::runtime", "soketto::connection::Sender::flush", "<tokio::net::tcp::stream::TcpStream as tokio::io::async_write::AsyncWrite>::poll_write", "mio::net::tcp::stream", "__send"];
        assert_eq!(classify(&st), ("socket", "syscall:socket"));
    }

    #[test]
    fn epoll_and_futex_are_tokios() {
        assert_eq!(classify(&["tokio::runtime::scheduler", "mio::poll::Poll::poll", "epoll_wait"]).0, "tokio");
        assert_eq!(classify(&["tokio::runtime::park", "std::sys::pal::unix::futex::futex_wait", "syscall"]).0, "tokio");
    }

    #[test]
    fn the_gate_wins_over_plexus_core_that_called_it() {
        let st = ["tokio::x", "plexus_core::plexus::plexus::DynamicHub::route_with_ctx", "plexus_core::plexus::grant_gate::decide", "plexus_auth_core::grants::Gate::check", "hashbrown::map::x"];
        assert_eq!(classify(&st).0, "gate");
    }
}
