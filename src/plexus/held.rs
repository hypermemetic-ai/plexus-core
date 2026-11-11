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
//! A sign-in's own end (`expires_at`, AUTH-11) is not a move: a call open
//! in process runs on past it, and what it asks after is refused (KEEL-51).
//! On a socket the transport closes the connection when the sign-in ends,
//! and tells each open call first (`wire::FrameSink::end_saying`).
//!
//! **What "no longer holds" means** ([`redecide`]):
//!
//! | admitted | asked again | ends when |
//! |---|---|---|
//! | on targets (a param the gate reads) | every target, [`Reach::allows`] | any target is no longer allowed |
//! | on `*` or at a door (a whole-service method, KEEL-31, ONE-7) | [`Reach::recheck`] | the grant is no longer held there |
//! | with no target (a `list`, a `watch`) | [`Reach::recheck`] | the grant is held nowhere, **or the reach lost a scope it had** |
//!
//! The last row is the safe rule: a read with no target answers from the
//! scopes its reach held, and the method may have read them already, so a
//! reach that narrowed ends the call and the client asks again under the new
//! one. A method that follows its reach itself — menger's `watch`, which
//! asks again at every move, says `entered` / `left` and re-scopes in place,
//! and ends itself (`watch_closed`) when nothing is held — says so with
//! [`crate::call::follows_its_reach`], and is left to it. A duplex call is
//! left to its input half, which asks the same rule.
//!
//! **Not held**: a call admitted on a `public` grant or on a grant every
//! signed-in caller holds (`auth.whoami`), an anonymous caller's, an
//! introspection call, and every call of a service with no gate.
//!
//! **Cost.** Nothing a item: the generation is one atomic load a poll, and
//! the gate is asked only when it moved — once a move for each call held,
//! O(open calls) a move. A call's stream is the box the dispatch already
//! made (the context's, `InCall`); it holds the gate, the targets the
//! dispatch read anyway, and a subscription to the generation, woken only
//! while the method has nothing ready.

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

/// The call's end, as its one error item.
fn end_item(ns: &str, e: &PlexusError) -> PlexusStreamItem {
    PlexusStreamItem::from_plexus_error(StreamMetadata::new(vec![ns.into()], PlexusContext::hash()), e, false)
}

/// What woke the held call.
enum Woke {
    Item(Option<PlexusStreamItem>),
    Moved,
}

/// `inner`, each poll of it inside `ctx` (as [`crate::call::InCall`]), held
/// to `ctx`'s admission: decided again by [`redecide`] when `service`'s
/// gate's generation moves past `seen` (read before the dispatch decided).
/// A service with no gate holds nothing.
pub(crate) fn held(ctx: CallContext, service: super::plexus::DynamicHub, seen: u64, targets: Vec<String>, inner: PlexusStream) -> PlexusStream {
    if service.gate().is_none() {
        return Box::pin(crate::call::InCall::new(ctx, inner));
    }
    Box::pin(async_stream::stream! {
        let Some(gate) = service.gate() else { return };
        let ns = service.runtime_namespace();
        let mut inner = Some(inner);
        let mut seen = seen;
        let generation = gate.generation();
        let mut moves = generation.subscribe();
        'held: loop {
            // The generation moved since it was last decided: asked again,
            // once — unless the call answers for its own reach.
            let now = generation.current();
            if now != seen {
                seen = now;
                if !ctx.holds_itself() {
                    let refused = match ctx.reach() {
                        Some(reach) => redecide(gate, reach, &targets).err(),
                        None => Some(Refusal::Unauthenticated),
                    };
                    if let Some(why) = refused {
                        // The method's stream goes first: its work stops now,
                        // whether or not its caller reads the item.
                        drop(inner.take());
                        yield end_item(ns, &PlexusError::from(why));
                        return;
                    }
                }
            }
            let mut changed = std::pin::pin!(moves.changed());
            loop {
                let woke = std::future::poll_fn(|cx| {
                    let Some(stream) = inner.as_mut() else { return Poll::Ready(Woke::Item(None)) };
                    if let Poll::Ready(item) = crate::call::poll_in(&ctx, stream, cx) {
                        return Poll::Ready(Woke::Item(item));
                    }
                    if changed.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Woke::Moved);
                    }
                    Poll::Pending
                })
                .await;
                match woke {
                    Woke::Item(Some(item)) => {
                        yield item;
                        if generation.current() != seen {
                            continue 'held;
                        }
                    }
                    Woke::Item(None) => return,
                    // A closed channel (the gate gone) wakes once; the
                    // atomic is read again either way.
                    Woke::Moved => continue 'held,
                }
            }
        }
    })
}
