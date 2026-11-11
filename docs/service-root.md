# The service root

A service's top level is one table of peers, by name. `peer(name)` answers
an entry, and routing walks from it: `<name>.<method>` is the entry's
method, `<name>.<child>.<method>` its child's.

| call | what it does |
| -- | -- |
| `.register(x)` | an entry, at build |
| `--child name=ws://…` (`ChildArgs`) | a `RemoteChild` entry, at build |
| `root().insert(x)` | an entry, while the service serves |
| `root().replace(x)` | the same, taking the name over |
| `root().insert_peer(name, peer, replace)` | any `Peer`, under a name of its own |
| `root().remove(name)` | the entry is gone |
| `root().names()`, `root().contains(name)` | what is served |
| `root().hash()`, `root().watch()` | the service's hash, and each change to it |

<!-- tests/docs_service_root.rs -->
```rust
let service = Arc::new(DynamicHub::new("myservice"));
let root = service.root();
let mut changes = root.watch();

root.insert(WeatherActivation).unwrap();
assert_eq!(root.names(), ["weather"]);
assert!(root.peer("weather").await.is_ok());

let sky = Arc::new(WeatherActivation) as Arc<dyn Peer>;
assert_eq!(root.insert_peer("sky", sky, false), Ok(false));
assert_eq!(root.names(), ["sky", "weather"]);

assert!(root.remove("weather"));
assert!(!root.contains("weather"));

assert!(changes.has_changed().unwrap());
assert_eq!(*changes.borrow_and_update(), root.hash());
```

Every `Activation + ChildRouter` is a `Peer`.

## What reads the table

Routing, the gate's index, `<service>.schema`, `.hash`, `.ir` and the
schema's `children` all read the table. A change moves the service's hash,
and `root().watch()` is told the hash after it.

## Names

A top-level name is one segment of letters, digits, `_` and `-`
(`RootError::BadName`). A name that is taken is refused
(`RootError::Taken`) unless the call replaces. The service's own name and
its own methods (`call`, `hash`, `hashes`, `ir`, `schema`) are refused
(`RootError::Shadows`): the service's own name answers the root itself.

## How an entry is reached

Every entry is reached through `<service>.call`, which is what synapse and
the generated clients send. On a service without a gate, an entry
registered at build also has direct `<namespace>.<method>` RPC names. An
entry inserted while the service serves has none. On a service with a gate
every call goes through `<service>.call`, and the gate admits an inserted
entry as it does any activation: by the roles that list its grants.
