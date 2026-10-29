//! PERF-5: a Plexus call from syscall to socket — the harness.
//!
//! - [`alloc`] — the counting global allocator (installed here, so every
//!   binary, test and bench of this crate counts).
//! - [`hist`] — HdrHistogram latency.
//! - [`openloop`] — intended send times (no coordinated omission).
//! - [`rawws`] — the raw WebSocket client: pre-built frames, blocking
//!   sockets, a scan instead of a parse.
//! - [`echo`] — the echo service: `bench.once`, `bench.count`, behind
//!   the house's gate, served by plexus-transport's WebSocket.
//! - [`procstat`] — a process's syscalls, CPU and context switches from /proc.
//! - [`frames`] — our own frames, for the codec table.
//! - [`layers`] — a sampled stack → the layer it is charged to.

pub mod alloc;
pub mod echo;
pub mod frames;
pub mod hist;
pub mod layers;
pub mod micro;
pub mod openloop;
pub mod procstat;
pub mod rawws;

#[global_allocator]
static GLOBAL: alloc::Counting = alloc::Counting;
