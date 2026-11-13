# A call is held to its admission

A gated service decides a call once, at its dispatch, and then holds it to
that decision while it runs. When the gate's grants generation moves (a
grant or a revoke, a role edited, a sign-out, a peer admitted or removed),
every open call a signed-in caller made on a grant is decided again, once,
by the rule it was admitted by (`src/plexus/held.rs`, `redecide`):

| admitted | ends when |
| -- | -- |
| on targets | any target is not allowed |
| on `*`, or at a door | the grant is not held there |
| with no target (a `list`, a `watch`, a wait) | the grant is held nowhere, or the reach lost any scope it had when the call opened |

A call that does not hold ends with one `forbidden` item (`unauthenticated`
for a sign-in that ended), and the method's stream is dropped at once: its
work stops, a call it forwarded is unsubscribed, and the calls made back
under it end. A call is also ended when its sign-in ends (`expires_at`; a
capped session's the same), on every path. A call with an input half is
held the same way for its whole life.

Public calls, calls on a grant every signed-in caller holds, and anonymous
calls are not held. Nothing is asked per item: one decision per open call
per move.

## A method's body is held more loosely than its stream

While a call is still routed (its method's body running before it returns a
stream: a unary method's whole work, a long `async fn`), the third row is
only "the grant is held somewhere". A reach that lost one scope ends a
targetless call's stream, never its body half-way, so another admin's
grant-then-revoke on a scope of its own cannot cut a caller's write between
its steps.

A scope lost while the body ran is asked of the stream once, when it is
handed over. The stream's first item goes out if it is ready at its first
poll (a unary write's answer), then the call ends `forbidden` if the reach
does not hold. A stream with nothing ready then is asked at once.

A body on targets, or admitted on `*` or at a door, is held as its stream
is. A body whose caller holds the grant nowhere, or whose sign-in ended, is
dropped at the await it is on.

**What a service must make safe to cut:** every method body with more than
one step that writes. A revoke of its caller, or its sign-in's end, stops it
between steps. Reserve-then-commit with a release on drop, one transaction,
or an idempotent retry; never two writes the reader assumes go together.

## A caller's own write is not held against it

A call whose write moves the grants generation (a revoke of its caller's
own grant, a role edit that drops the grant it was called under,
`auth.logout`) is not asked about those moves: it finishes and its caller
reads the write's answer. The generation tells the call that moved it, in
the moving task: plexus-core's own `auth` writes, and a service's store that
moves its generation inside its write (`AuthSetup::with_generation`), alike.

Only the call's own run of moves is passed over. A move made by anything
else, before, between or after, is asked as usual.

The mark is made in the task that bumps the generation, inside the call. A
store that bumps it from `spawn_blocking`, a detached task or a forwarder is
not marked, and its caller reads `forbidden` for its own revoke.

## A scoped admin can end another's open reads

The last row of the table is the safe reading for confidentiality: a read
with no target may already have answered from a scope its reach has lost.
It also means that an admin of any scope `S` can end any principal's open
targetless reads: grant the principal a role on `S`, wait for the principal
to open a read, revoke it. The end is said (`forbidden`, naming `S`) and the
client may open the read again.

A long-lived targetless method, a `watch` or a long wait, follows its own
reach: it asks `Reach::recheck` at each move, re-scopes in place, ends
itself when nothing is held, and says so once with
`plexus_core::call::follows_its_reach()`. The hold then leaves it to the
method. Only the method the gate dispatched for this call can say it: not a
method it calls through the router, and not a service with no gate. A
method's own code calling another activation's Rust function directly runs
in the same call, and its word is the method's. A call that follows its
reach still ends at its sign-in's end.

## An end by the server says nothing about a write

A call ended mid-write (its caller's grant revoked while it runs) drops the
method at its next await: a write that already landed stays, and its caller
reads `forbidden`, not the write's answer. A client that must know asks
again. plexus-core's own grant writes (`auth.revoke`, `auth.role_set`,
`auth.logout`) move the generation even when they are ended mid-write.
