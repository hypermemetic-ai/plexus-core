# Benchmarking plexus-core

> **PLX-101, 2026-07-26.** This crate's benchmarks are **decision inputs, not
> diagnostics.** Decision gate 2 (PLX-74/PLX-80) and PLX-88's "leave it" verdict
> were both resolved on measured numbers. Until PLX-101 those numbers were
> measured against a dependency resolution nobody recorded, because
> `.gitignore` ignored `Cargo.lock`.

## The rule

**A benchmark number is not quotable without its resolution.**

Every bench binary prints a resolution banner before the first measurement:

```
==== resolution (PLX-101) — bench: turn_profile ====
lock-fingerprint : 64ae19616b28ac56  (FNV-1a over Cargo.lock, all packages)
toolchain        : stable-aarch64-apple-darwin
host             : macos / aarch64
profile          : optimized (debug_assertions off)
perf-relevant resolved versions:
    tokio          1.48.0
    ...
```

Quote the `lock-fingerprint` with the number. **Two numbers with different
fingerprints are not comparable.** The banner is also written to
`target/criterion/resolution-<bench>.txt` so a saved result set carries it.

Implementation: `benches/common/resolution.rs`, `include_str!`d from
`Cargo.lock` at compile time — so the banner is an attribute of the binary that
produced the numbers, and a bench **cannot build without a lock file**.

## Why `Cargo.lock` is committed

Committing the lock is unconventional for a library. We do it anyway, and the
reason is measured, not stylistic — see the finding below. Two things it does
**not** do:

- It does **not** pin tokio for anyone who depends on `plexus-core`. The
  manifest still says `tokio = { version = "1.0", ... }`; cargo ignores a
  dependency's lock file. Only this crate's own builds, tests and benches are
  pinned.
- It does **not** freeze us. Bumping the lock is a normal reviewable commit —
  it just stops being *invisible*, and re-measurement becomes part of the bump.

The lock is currently pinned at **tokio 1.48.0**, which is the resolution every
recorded figure in the PLX-74 / PLX-80 / PLX-88 / PLX-97 corpus was measured
under. Pinning there is what makes that corpus retroactively comparable.

## Finding: the 5.3x is a tokio behaviour change, upstream, at 1.50.0

PLX-97 observed `ladder_current/full_turn` move **2.7 µs → 14.0 µs** in a fresh
worktree. PLX-101 reproduced and attributed it.

### It is not machine load, and not plexus

Two builds of identical plexus-core source differing only in `Cargo.lock`, run
**interleaved on the same machine under the same ambient load**, three rounds:

| bench (`ladder_current`) | tokio 1.48.0 | tokio 1.53.1 |
|---|---|---|
| `legacy_echo_once` | 834–878 ns | 846–869 ns |
| `spawn_noop_join` | 929–956 ns | 12.34–13.2 µs |
| `full_turn` | 2.62–2.97 µs | 13.8–16.3 µs |

`legacy_echo_once` is **unchanged**. A machine-load artefact would have moved
it too. The delta is confined to `tokio::spawn` + `JoinHandle` on a
**current-thread** runtime.

### It is tokio 1.50.0, isolated from plexus entirely

A standalone probe crate depending on nothing but tokio
(`block_on(async { yield_now().await })` on a current-thread runtime — **no
spawn, no plexus code**):

| tokio | ns/iter |
|---|---|
| 1.48.0 | 862 |
| 1.49.0 | 845 |
| **1.50.0** | **12 736** |
| 1.51.0 | 12 914 |
| 1.52.0 | 12 112 |
| 1.53.1 | 12 223 |

`mio` (1.2.2) and `libc` (0.2.189) resolve identically at 1.49.0 and 1.50.0, so
this is tokio's own code and not a transitively re-resolved sys crate.

### The mechanism, and what it is not

- **Current-thread only.** Multi-thread `spawn(noop).await` went 8.60 µs →
  6.65 µs, i.e. slightly *faster*.
- **Per park/unpark, not per task.** 64 spawns joined inside one `block_on`
  cost ~570 ns each, versus ~12.5 µs for one spawn awaited alone. The cost
  amortizes across concurrent work.
- **`block_on` with no yield is unchanged** at ~92 ns.

Upstream, the only change on this path between 1.49.0 and 1.50.0 is
[tokio#7834](https://github.com/tokio-rs/tokio/pull/7834) ("avoid redundant
unpark in current_thread scheduler"), with
[#7835](https://github.com/tokio-rs/tokio/pull/7835) as its follow-on.
`Wake::wake_by_ref` for the current-thread `Handle` stopped calling
`driver.unpark()` when the wake originates on the runtime itself. Before 1.50
that unconditional `unpark()` left the driver permanently pre-armed (on Darwin,
a pending `EVFILT_USER` in the runtime's kqueue), so every subsequent park
returned immediately. Removing it means the park now genuinely transits the
kernel wait path — roughly the ~12 µs we measure. Related upstream regression
reports: [#8212](https://github.com/tokio-rs/tokio/issues/8212),
[#7570](https://github.com/tokio-rs/tokio/issues/7570).

**Caveat, stated plainly:** the source change removes a syscall, so the source
alone predicts a small *speedup*. The 15x is a second-order Darwin kqueue
effect. The attribution to #7834 is high-confidence (it is the only diff on
this path); the Darwin-level mechanism is inferred, not instrumented. Settling
it would need a syscall trace, which is out of scope for PLX-101.

### Verdict: **not a measurement artefact, not a plexus regression, and not a
production problem** — but it *is* a benchmark-validity problem

Servers run the multi-thread runtime, which is unaffected. What the change
destroys is the **low-variance current-thread column** that PLX-88 used as its
attribution instrument, precisely because a current-thread spawn used to be a
local enqueue. On tokio ≥ 1.50 that column measures a Darwin park round trip.

## What re-measurement did and did not change

Re-run under the pinned resolution (lock fingerprint `64ae19616b28ac56`,
tokio 1.48.0), against the recorded figures:

| recorded | re-measured | verdict |
|---|---|---|
| gate 2 miss-row delta +10.4 ns = 1.28% of bar | +10.06 ns = 1.18% of an 853 ns bar | **PASS, unchanged** |
| gate 2 hit-row delta +52 ns = 6.0–6.2% (known to fail as literally written) | +55.6 ns = 6.5% | **unchanged, including the known failure** |
| PLX-88 total turn 2633 ns (current) | 2656 ns | reproduces (+0.9%) |
| PLX-88 `tokio::spawn` rung 965.7 ns = 36.7% | 987.3 ns = 37.2% | reproduces |
| PLX-88 `ladder_multi/full_turn` 8.32 µs | 7.19–9.82 µs | reproduces (high variance) |
| PLX-88 concurrent 1.96 µs/turn vs 0.90 µs legacy | 1.84 µs vs 0.90 µs | reproduces |

**Neither verdict changes.** Gate 2 is resolution-*insensitive* — it re-passes
on tokio 1.53.1 too (+9.25 ns = 1.12%), because it measures name resolution,
which never parks.

**One recorded artefact is resolution-*bound*: PLX-88's attribution table.**
On tokio ≥ 1.50 the same table reads:

| component | @ tokio 1.48.0 | @ tokio 1.53.1 |
|---|---|---|
| `tokio::spawn` + `JoinHandle` | 987 ns (37.2%) | 12 098 ns (90.2%) |
| `TurnId::new()` (uuid v4) | 452 ns (17.0%) | 428 ns (3.2%) |
| total turn (`ladder_current/full_turn`) | 2 656 ns | 13 411 ns |

The *absolute* numbers for everything below the spawn are unchanged; only the
spawn rung and therefore every percentage moves. PLX-88's follow-up #1 (uuid
`fast-rng`) is still worth ~430 ns, but "16% of the turn" is a statement about
tokio 1.48.0, not about the turn. **Percentages from that table must be quoted
with the lock fingerprint.**

PLX-88's *verdict* survives because its load-bearing evidence was the
concurrent multi-thread measurement, which is resolution-insensitive.

## Running the benches

```sh
cargo bench --bench dispatch                              # decision gate 2
cargo bench --bench turn_profile --features profiling     # PLX-88 attribution
```

`turn_profile` needs the `profiling` feature; it gates `runtime::profile`, the
staged ablation ladder.

**Measure on a quiet machine.** `ladder_multi/*` has ±1 µs variance even idle.
If you must measure under load, run the two arms **interleaved** and compare
`legacy_echo_once` across them as a control — that is how PLX-101 separated the
tokio change from ambient load.
