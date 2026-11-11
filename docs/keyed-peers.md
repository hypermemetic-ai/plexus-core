# Keyed peers

A child is an activation served from another process and mounted on a
service (`RemoteChild`). A keyed child has an Ed25519 key of its own. These
are the rules a keyed child and the service that mounts it apply, in the
order the code checks them. The code is `src/plexus/remote_child/` and
`src/plexus/peer_token.rs`.

## Before a child runs a hop

A hop is a forwarded call: `{ns}.call` for a method M. A schema call needs
none of this.

1. A child with a key, or one verifying tokens addressed to a key, is
   served only by `serve_child_proven`. It takes a `Proven`: a type with no
   constructor from a string, made only by `KeyedUpgrade::verify` checking
   the upgrade's `plexus-key.` proof. `serve_child_ws` does this. The child
   believes hops from that principal alone. `serve_child_with` refuses a
   keyed child, whatever `ChildPeer` it is given.
2. A keyless child that verifies nothing (`serve_child_with`) believes
   every sender its `ChildPeer` takes. Served as `ChildPeer::Pipe` on a
   WebSocket, it believes every sender who can reach that socket, as
   whoever the frame claims to be. **Do not do this.** A keyless child
   belongs on its parent's stdin and stdout, or on a socket only that
   parent can open. A child reachable over a network has a key and is
   served with `serve_child_ws`. On `ChildPeer::connection` the sender is
   the string it was given, which proves nothing by itself.
3. With a verifier, the hop's token must verify: an EdDSA JWS signed by a
   trusted JWKS key (`iss` = `kid`), `aud` this child, within its times,
   naming `hop.call` and M, its `sub` the hop's caller, its scope holding
   the hop's grant on every scope the hop says.
4. Its sender must be proven by `hop.proof` over (token, M, `hop.call`). A
   token bound to this child's own key (or, on a pipe, to none) is the
   service's forward: the proof is by the issuer's key, and on a connection
   the sender is one `ChildPeer` takes. A token bound to another key is an
   exchanged one: the proof is by that key, over a connection proven as it,
   which the hop names. Only then is the token's `jti` spent, once.
5. Then the child's own check runs (the hop's grant is M or M's slot), and
   M runs as the hop's caller, within the scopes the hop says.

## Before a service mounts a keyed peer

`RemoteChild::connect`:

1. The service dials with its own key proof on the upgrade
   (`ChildOptions::key`; in plexus-dyn, `<data_dir>/dial.key` by default),
   so its principal is the `key:` the peer's transport proves.
2. It asks `_info {nonce, asker}`. A peer that names a key must prove it
   with `plexus-peer-key/v2` over (nonce, backend, the asker its connection
   proved), checked against the service's own principal. The mount is
   refused when that principal is not a key (`keyed_mount_needs_a_key`) or
   the proof was made for anyone else.
3. plexus-dyn pins the key with the peer's identity. A remount proving
   another key is refused (`identity_changed`), and so is a key another
   peer holds (`key_in_use:`).
4. Tokens are minted for that key only while it is mounted and not
   revoked, by a service whose principal is a key. Each forwarded hop
   carries the service's proof (`TokenIssuer::prove_forward`).
5. An exchange (`TokenIssuer::exchange_decided`; plexus-dyn's
   `dyn.exchange`) is the service's decision whether the presenter may
   reach the audience. A subject token is exchanged once per (`jti`,
   audience, method), and the token it answers is bound to the presenter's
   key.

## Peer tokens

A token is a compact JWS of a JWT, signed EdDSA, `typ` `plexus-peer+jwt`.

| claim | what |
| -- | -- |
| `iss` | the issuing service's key, `key:<hex>` |
| `sub` | the original caller |
| `act` | the actor chain, nearest first |
| `aud` | exactly one peer: its key, or `pipe:<name>` for a child on the issuer's own pipe |
| `scope` | space-separated `grant@scope` entries |
| `cnf.jkt` | the thumbprint of the key that presents it; absent for a pipe |
| `call`, `method` | the forwarded call's id and the method it names |
| `jti`, `iat`, `exp` | unique; `exp − iat` is at most 60 s |

Clocks may differ by 30 s. Every mint and exchange writes one audit record
as a `tracing` event on target `plexus::audit`: never the token, never a
proof.

## Replay

An upgrade's key proof is taken once while its 60 s window lasts, and a
token's `jti` once while it lives.

`KeyedUpgrade` holds at most 4096 proofs (`UPGRADE_LEDGER_MAX`). Full, it
refuses an upgrade until proofs leave their window; it never forgets a
proof early. The dialer is told `this child holds 4096 key proofs in their
60 s window: a new upgrade is refused until some expire`, and the child
logs `child upgrade ledger full` on target `plexus::audit` at most once
per 10 s. So a child takes at most 4096 upgrades a minute. A flood can deny
upgrades for a minute, and cannot replay one.

Both ledgers are kept in memory. A restarted child forgets, so a proof or
token captured in the 60 s before a restart can be replayed to it once
after it: a token only while it lives, at most until its `exp`.

## Key files

A key file is the user's own, mode 0600, in a directory of mode 0700, and
is never read through a symbolic link.

## The dial proof

A child dial's key proof is plexus-wire spec/00's key proof, signed as the
reserved agent `plexus.child-dial` (`CHILD_DIAL_AGENT`). `agent` is in the
signed bytes, and a child takes only that agent, so a sign-in proof
replayed to a child at the same URL is refused.

A server's sign-in (plexus-auth-core's `KeyProofAdapter`) takes a dial
proof as the dialing key's sign-in. A dial proof is addressed to the dialed
URL and usable only there, and it is how a service mounts another service
behind key sign-in (`--child far=wss://…`, `dyn.connect`).
