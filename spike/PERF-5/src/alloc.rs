//! A counting global allocator: every allocation, reallocation and free, and
//! the bytes asked for, counted process-wide and per thread. Off until
//! `enable(true)`, so a latency run pays one relaxed load per allocation.
//! PERF-17 E6: the allocator underneath is glibc's (`System`), or mimalloc
//! with `--features mimalloc`.

use std::alloc::{GlobalAlloc, Layout};
#[cfg(not(feature = "mimalloc"))]
use std::alloc::System as Inner;
#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc as Inner;

/// Which allocator is underneath, for the rows.
pub const INNER: &str = if cfg!(feature = "mimalloc") { "mimalloc" } else { "glibc" };
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

pub struct Counting;

static ON: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static FREES: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static T_ALLOCS: Cell<u64> = const { Cell::new(0) };
    static T_REALLOCS: Cell<u64> = const { Cell::new(0) };
    static T_FREES: Cell<u64> = const { Cell::new(0) };
    static T_BYTES: Cell<u64> = const { Cell::new(0) };
}

#[inline]
fn bump(c: &'static std::thread::LocalKey<Cell<u64>>, n: u64) {
    let _ = c.try_with(|c| c.set(c.get() + n));
}

#[inline]
fn count_alloc(bytes: usize) {
    if ON.load(Relaxed) {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(bytes as u64, Relaxed);
        bump(&T_ALLOCS, 1);
        bump(&T_BYTES, bytes as u64);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_alloc(layout.size());
        Inner.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_alloc(layout.size());
        Inner.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ON.load(Relaxed) {
            FREES.fetch_add(1, Relaxed);
            bump(&T_FREES, 1);
        }
        Inner.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ON.load(Relaxed) {
            REALLOCS.fetch_add(1, Relaxed);
            bump(&T_REALLOCS, 1);
            count_alloc(new_size.saturating_sub(layout.size()));
        }
        Inner.realloc(ptr, layout, new_size)
    }
}

pub fn enable(on: bool) {
    ON.store(on, Relaxed);
}

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Snap {
    pub allocs: u64,
    pub reallocs: u64,
    pub frees: u64,
    pub bytes: u64,
}

impl std::ops::Sub for Snap {
    type Output = Snap;
    fn sub(self, o: Snap) -> Snap {
        Snap {
            allocs: self.allocs - o.allocs,
            reallocs: self.reallocs - o.reallocs,
            frees: self.frees - o.frees,
            bytes: self.bytes - o.bytes,
        }
    }
}

pub fn snapshot() -> Snap {
    Snap { allocs: ALLOCS.load(Relaxed), reallocs: REALLOCS.load(Relaxed), frees: FREES.load(Relaxed), bytes: BYTES.load(Relaxed) }
}

pub fn thread_snapshot() -> Snap {
    Snap {
        allocs: T_ALLOCS.with(Cell::get),
        reallocs: T_REALLOCS.with(Cell::get),
        frees: T_FREES.with(Cell::get),
        bytes: T_BYTES.with(Cell::get),
    }
}
