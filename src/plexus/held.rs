//! KEEL-59 · a call held to its admission while it runs.
//!
//! A gated service decides a call once, at its dispatch, and the call then
//! runs under the reach the gate answered. When the gate's grants generation
//! moves — a grant or a revoke, a role edited, a team changed, a sign-out,
//! a consent — every call it holds is decided again, once, by the rule it was
//! admitted by ([`redecide`], the one rule a duplex call's input half asks
//! too, `duplex_gate`). One that no longer holds ends with **one** typed
//! error item — `forbidden` with its usual fields, or `unauthenticated` for a
//! sign-in that ended — and its stream is dropped at that moment, so the
//! method's work stops; a call it forwarded to a peer is unsubscribed by the
//! drop (spec/12 rule 6), and the calls that peer was making back under it
//! end with it.
//!
//! A sign-in's own end (`expires_at`, AUTH-11, a capped session's the same)
//! ends a held call at that moment, on every path — in process, through a
//! bridge, across a hop — with one `unauthenticated` item (M2): a call that
//! waits is woken by a timer made with its wait; one that never waits looks
//! at the clock every 64 items. On a socket the transport also closes the
//! connection then, and tells each open call first
//! (`wire::FrameSink::end_saying`).
//!
//! **What "no longer holds" means** ([`redecide`]):
//!
//! | admitted | asked again | ends when |
//! |---|---|---|
//! | on targets (a param the gate reads) | every target, [`Reach::allows`] | any target is no longer allowed |
//! | on `*` or at a door (a whole-service method, KEEL-31, ONE-7) | [`Reach::recheck`] | the grant is no longer held there |
//! | with no target (a `list`, a `watch`) | [`Reach::recheck`] | the grant is held nowhere, **or the reach lost a scope it had** |
//!
//! While the call is still routed (its method's body running, before it has
//! a stream: [`routing`]), the last row is only "the grant is held
//! somewhere" ([`redecide_body`], N1): a third party's grant-then-revoke on
//! a scope of its own never cuts a body between its steps. A move judged by
//! that rule alone owes the stream's full rule once at the handover (P1):
//! after the stream's first item if it is ready at its first poll, else at
//! once. A call whose
//! own write made a move is not asked about it (N2, `call::own_move`); a
//! call whose peer was cut off keeps its own end while that end is on its
//! way (N3) — only a call into the peer the dispatch itself opened (P2).
//!
//! The last row is the safe rule: a read with no target answers from the
//! scopes its reach held, and the method may have read them already, so a
//! reach that narrowed ends the call and the client asks again under the new
//! one. A method that follows its reach itself — menger's `watch`, which
//! asks again at every move, says `entered` / `left` and re-scopes in place,
//! and ends itself (`watch_closed`) when nothing is held — says so with
//! [`crate::call::follows_its_reach`], and is left to it — the dispatched
//! method's word only, never a callee's (I1: a context derived once the
//! call is routed carries its claim no further). A duplex call is held like
//! any other for its whole life (H1): its input half asks the same rule
//! while it is open and says it sooner; once the client ended its input or
//! the handler let it go, this hold is what ends it. Either way one end.
//!
//! A call refused here is never polled again (L3): its stream is dropped
//! and the refusal is its last item. An end by the server says nothing of
//! a write the method was making (L2): one that landed before the drop
//! stays, and its caller reads the refusal, not the write's answer.
//!
//! **Not held**: a call admitted on a `public` grant or on a grant every
//! signed-in caller holds (`auth.whoami`), an anonymous caller's, an
//! introspection call, and every call of a service with no gate.
//!
//! **Cost.** Nothing an item: a poll is one atomic load beside the method's
//! own poll, and the gate is asked only when the generation moved — once a
//! move for each call held, O(open calls) a move (10,000 open calls: every
//! one decided again in about 4.5 ms, every one ended by a revoke in about
//! 21 ms; `tests/keel59_cost.rs`). A call's stream is still the one box the
//! dispatch made, larger (the service, the targets the dispatch read
//! anyway); a call that waits subscribes to the generation once, one
//! allocation kept until a move wakes it. A gated one-item call in process:
//! about +70–80 ns and no allocation more (1.10 → 1.18 µs, 30 allocations).

use std::future::Future;
use std::task::Poll;

use plexus_auth_core::grants::{Gate, Reach, Refusal};

use super::context::PlexusContext;
use super::plexus::PlexusError;
use super::streaming::PlexusStream;
use super::types::{PlexusStreamItem, StreamMetadata};
use crate::call::CallContext;

/// Decide `reach` again by the rule it was admitted by: every target the
/// dispatch checked, or — none — the reach whole, which must still hold every
/// scope it held ([`Reach::held_on`] at the admission). `Err` is why it no
/// longer holds, said as the gate says it.
pub(crate) fn redecide(gate: &Gate, reach: &Reach, targets: &[String]) -> Result<(), Refusal> {
    if !targets.is_empty() {
        for t in targets {
            if !reach.allows(t) {
                // Why, said as the gate says it: the reach's own rule first.
                let why = reach.recheck().err().or_else(|| gate.check(reach.caller(), reach.grant()?, Some(t)).err());
                return Err(why.unwrap_or(Refusal::Unauthenticated));
            }
        }
        return Ok(());
    }
    let now = reach.recheck()?;
    if now.is_everywhere() {
        return Ok(());
    }
    match reach.held_on().iter().find(|s| !now.held_on().contains(s)) {
        None => Ok(()),
        Some(lost) => {
            let grant = reach.grant().cloned().unwrap_or_else(|| plexus_auth_core::grants::Grant::new(""));
            let roles = gate.roles_listing(&grant);
            Err(Refusal::MissingGrant { grant, scope: lost.clone(), roles, held_on: now.held_on().to_vec() })
        }
    }
}

/// KEEL-59 (N1): decide a call whose method's body is still running (it is
/// being routed) again. On targets, or at `*` / a door, as [`redecide`];
/// with no target, only that the grant is still held somewhere — a reach
/// that lost one scope ends the call's stream, never its body half-way, so
/// a third party's grant-then-revoke on a scope of its own cannot cut
/// another caller's write between its steps.
pub(crate) fn redecide_body(gate: &Gate, reach: &Reach, targets: &[String]) -> Result<(), Refusal> {
    if !targets.is_empty() {
        return redecide(gate, reach, targets);
    }
    reach.recheck().map(|_| ())
}

/// The call's end, as its one error item.
fn end_item(ns: &str, e: &PlexusError) -> PlexusStreamItem {
    PlexusStreamItem::from_plexus_error(StreamMetadata::new(vec![ns.into()], PlexusContext::hash()), e, false)
}

/// The wait for the generation's next move: its own receiver inside, so it
/// lives across polls (made only once the method has nothing ready).
type Wait = std::pin::Pin<Box<dyn Future<Output = Woke> + Send>>;

/// What ended a held call's wait.
enum Woke {
    Moved,
    /// The sign-in's `expires_at` came.
    Expired,
}

/// When the call's sign-in ends (M2): read once, when first needed.
#[derive(Clone, Copy)]
enum Ends {
    Unread,
    Never,
    At(std::time::SystemTime),
}

/// How many items a busy call yields between looks at the clock (one that
/// never waits never arms the timer).
const CLOCK_EVERY: u8 = 64;

/// What a held call ends with when its sign-in ends.
fn expired() -> PlexusError {
    PlexusError::Unauthenticated("your sign-in has expired: sign in again".into())
}

/// `inner`, each poll of it inside `ctx` (as [`crate::call::InCall`]), held
/// to `ctx`'s admission: decided again by [`redecide`] when `service`'s
/// gate's generation moves past `seen` (read before the dispatch decided).
/// A service with no gate holds nothing.
pub(crate) fn held(ctx: CallContext, service: super::plexus::DynamicHub, seen: u64, owed: bool, targets: Vec<String>, inner: PlexusStream) -> PlexusStream {
    if service.gate().is_none() {
        return Box::pin(crate::call::InCall::new(ctx, inner));
    }
    Box::pin(Held { ctx, service, seen, targets, inner: Some(inner), wait: None, ends: Ends::Unread, items: 0, owed: if owed { Owed::FirstItem } else { Owed::No } })
}

/// A held call's stream ([`held`]). A poll is one atomic load and the
/// method's own poll; the gate is asked only when the generation moved; the
/// wait for a move is made (one allocation) only when the method has
/// nothing ready, and kept until a move wakes it.
struct Held {
    ctx: CallContext,
    service: super::plexus::DynamicHub,
    seen: u64,
    targets: Vec<String>,
    /// `None` once over: ended by the method, or by the hold.
    inner: Option<PlexusStream>,
    wait: Option<Wait>,
    ends: Ends,
    /// Items since the clock was last read.
    items: u8,
    /// P1: the stream's full rule, owed from the body's hold.
    owed: Owed,
}

/// P1: what a stream owes after a body that was held by the body's rule
/// alone through a move.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owed {
    No,
    /// The first item, if it is ready at the first poll, goes out (a unary
    /// write's answer, made in its body); then the full rule.
    FirstItem,
    /// The full rule, now.
    Now,
}

impl Ends {
    /// When the sign-in ends, read from the call's identity once.
    fn at(&mut self, ctx: &CallContext) -> Option<std::time::SystemTime> {
        if let Ends::Unread = self {
            let at = ctx.auth().and_then(|a| a.metadata.get(plexus_auth_core::auth::EXPIRES_AT_KEY)).and_then(serde_json::Value::as_i64);
            *self = match at {
                Some(at) => Ends::At(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at.max(0) as u64)),
                None => Ends::Never,
            };
        }
        match self {
            Ends::At(t) => Some(*t),
            _ => None,
        }
    }

    /// The sign-in has ended.
    fn over(&mut self, ctx: &CallContext) -> bool {
        self.at(ctx).is_some_and(|t| std::time::SystemTime::now() >= t)
    }
}

/// The call's end: its stream dropped first, never polled again.
fn end(inner: &mut Option<PlexusStream>, wait: &mut Option<Wait>, ns: &str, e: PlexusError) -> Poll<Option<PlexusStreamItem>> {
    *inner = None;
    *wait = None;
    Poll::Ready(Some(end_item(ns, &e)))
}

/// The wait for the generation's next move, or the sign-in's end.
fn wait_for(generation: &plexus_auth_core::grants::GrantsGeneration, ends: Option<std::time::SystemTime>) -> Wait {
    let mut moves = generation.subscribe();
    Box::pin(async move {
        let expiry = async move {
            match ends.map(|t| t.duration_since(std::time::SystemTime::now()).unwrap_or_default()) {
                Some(left) => crate::rt::sleep(left).await,
                None => std::future::pending::<()>().await,
            }
        };
        let moved = async move {
            // A closed channel (the gate gone) never wakes again.
            if moves.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            () = moved => Woke::Moved,
            () = expiry => Woke::Expired,
        }
    })
}

/// The call being routed — its method's body running before it has a
/// stream (a unary method's whole work, a long `async fn`) — held as its
/// stream will be ([`held`]): decided again when the generation moves past
/// `seen`, ended at the sign-in's end. A call that no longer holds is
/// dropped there and answered as a stream of its one end. `targets` none:
/// not held, `routed` awaited as it is. `seen` is left where it was last
/// decided, for the stream's hold.
pub(crate) async fn routing<F>(ctx: &CallContext, service: &super::plexus::DynamicHub, seen: &mut u64, owed: &mut bool, targets: Option<&[String]>, routed: F) -> Result<PlexusStream, PlexusError>
where
    F: Future<Output = Result<PlexusStream, PlexusError>>,
{
    crate::call::hook_moves();
    let (Some(targets), Some(gate)) = (targets, service.gate()) else { return routed.await };
    let generation = gate.generation();
    let mut routed = std::pin::pin!(routed);
    let mut wait: Option<Wait> = None;
    let mut ends = Ends::Unread;
    let ended = |e: PlexusError| -> Result<PlexusStream, PlexusError> {
        let item = end_item(service.runtime_namespace(), &e);
        Ok(Box::pin(futures::stream::iter([item])))
    };
    std::future::poll_fn(|cx| loop {
        let now = generation.current();
        if now != *seen {
            let before = std::mem::replace(seen, now);
            wait = None;
            if !ctx.holds_itself() && !ctx.ended_by_peer() && !ctx.own_move(before, now) {
                let refused = match ctx.reach() {
                    Some(reach) => redecide_body(gate, reach, targets).err(),
                    None => Some(Refusal::Unauthenticated),
                };
                if let Some(why) = refused {
                    return Poll::Ready(ended(PlexusError::from(why)));
                }
                // P1: a call with no target was judged by the body's rule
                // alone ("held somewhere"): the stream's full rule is owed,
                // once, at the handover.
                if targets.is_empty() {
                    *owed = true;
                }
            }
            continue;
        }
        if let Poll::Ready(r) = routed.as_mut().poll(cx) {
            return Poll::Ready(r);
        }
        if wait.is_none() {
            if ends.over(ctx) {
                return Poll::Ready(ended(expired()));
            }
            wait = Some(wait_for(generation, ends.at(ctx)));
        }
        if generation.current() != *seen {
            continue;
        }
        match wait.as_mut().expect("made above").as_mut().poll(cx) {
            Poll::Ready(Woke::Moved) => wait = None,
            Poll::Ready(Woke::Expired) => return Poll::Ready(ended(expired())),
            Poll::Pending => return Poll::Pending,
        }
    })
    .await
}

impl futures::Stream for Held {
    type Item = PlexusStreamItem;

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<PlexusStreamItem>> {
        let this = self.get_mut();
        let Some(gate) = this.service.gate() else { return Poll::Ready(None) };
        let generation = gate.generation();
        loop {
            let Some(stream) = this.inner.as_mut() else { return Poll::Ready(None) };
            // P1: a move the body was held through by the body's rule alone
            // is asked of the stream by its full rule, once: after the first
            // item if that is ready at the first poll, else at once.
            match this.owed {
                Owed::No => {}
                Owed::FirstItem => {
                    this.owed = Owed::Now;
                    match crate::call::poll_in(&this.ctx, stream, cx) {
                        Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                        Poll::Ready(None) => {
                            this.inner = None;
                            return Poll::Ready(None);
                        }
                        Poll::Pending => continue,
                    }
                }
                Owed::Now => {
                    this.owed = Owed::No;
                    if !this.ctx.holds_itself() && !this.ctx.ended_by_peer() {
                        let refused = match this.ctx.reach() {
                            Some(reach) => redecide(gate, reach, &this.targets).err(),
                            None => Some(Refusal::Unauthenticated),
                        };
                        if let Some(why) = refused {
                            return end(&mut this.inner, &mut this.wait, this.service.runtime_namespace(), PlexusError::from(why));
                        }
                    }
                    continue;
                }
            }
            // The generation moved since it was last decided: asked again,
            // once — unless the call answers for its own reach.
            let now = generation.current();
            if now != this.seen {
                let before = std::mem::replace(&mut this.seen, now);
                this.wait = None;
                // A call whose peer was cut off has its own end on its way
                // (`child_unavailable`, saying why): the move the cut-off
                // made is not asked about it.
                if !this.ctx.holds_itself() && !this.ctx.ended_by_peer() && !this.ctx.own_move(before, now) {
                    let refused = match this.ctx.reach() {
                        Some(reach) => redecide(gate, reach, &this.targets).err(),
                        None => Some(Refusal::Unauthenticated),
                    };
                    if let Some(why) = refused {
                        // The method's stream goes first, never polled again
                        // (L3): its work stops now, whether or not its caller
                        // reads the item.
                        return end(&mut this.inner, &mut this.wait, this.service.runtime_namespace(), PlexusError::from(why));
                    }
                }
                continue;
            }
            if let Poll::Ready(item) = crate::call::poll_in(&this.ctx, stream, cx) {
                if item.is_none() {
                    this.inner = None;
                    return Poll::Ready(None);
                }
                // M2: a call that never waits looks at the clock now and
                // then; one that waits is woken by its timer.
                this.items = this.items.wrapping_add(1);
                if this.items % CLOCK_EVERY == 0 && this.ends.over(&this.ctx) {
                    return end(&mut this.inner, &mut this.wait, this.service.runtime_namespace(), expired());
                }
                return Poll::Ready(item);
            }
            // Nothing ready: wake at the next move, or at the sign-in's end.
            if this.wait.is_none() {
                if this.ends.over(&this.ctx) {
                    return end(&mut this.inner, &mut this.wait, this.service.runtime_namespace(), expired());
                }
                this.wait = Some(wait_for(generation, this.ends.at(&this.ctx)));
            }
            // A move between the read above and the subscription is read now.
            if generation.current() != this.seen {
                continue;
            }
            match this.wait.as_mut().expect("made above").as_mut().poll(cx) {
                Poll::Ready(Woke::Moved) => this.wait = None,
                Poll::Ready(Woke::Expired) => return end(&mut this.inner, &mut this.wait, this.service.runtime_namespace(), expired()),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
