## Calls (µs; medians of runs)

| src | label | scenario | rate | conns | inflight | p50 | p99 | p999 | calls/s | runs | load |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |

## Allocations and CPU per call

| run | allocs/call | bytes/call | spawned tasks/call | server CPU µs/call | vol cs/call |
| -- | -- | -- | -- | -- | -- |

## Streams (10,000 items)

| src | label | size | items/s | allocs/item | alloc B/item | wire B/item | frames/item | server CPU µs/item | runs | load |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |

## Codecs (ns per item, median of 3 runs)

| frame | codec | op | bytes | ns | allocs |
| -- | -- | -- | -- | -- | -- |

## In process

| group | bench | ns/op | allocs/op | bytes/op | runs |
| -- | -- | -- | -- | -- | -- |

## CPU shares (SIGPROF samples, server process)

**call** — 1455 samples · layers: socket 44.3%, tokio 25.4%, serde_json 10.1%, jsonrpsee 9.7%, plexus 6.5%, gate 4.1% · leaves: code 47.6%, syscall:socket 44.3%, syscall:park 5.0%, alloc 3.1%

**call64conns** — 4500 samples · layers: socket 38.9%, serde_json 20.0%, jsonrpsee 19.1%, plexus 9.2%, gate 7.2%, tokio 5.6% · leaves: code 53.2%, syscall:socket 38.9%, alloc 7.6%, syscall:park 0.3%

**stream4096** — 2017 samples · layers: socket 50.0%, serde_json 39.7%, jsonrpsee 6.3%, tokio 2.0%, plexus 1.7%, gate 0.2% · leaves: syscall:socket 50.0%, code 34.2%, alloc 15.2%, syscall:park 0.6%

**stream64** — 2358 samples · layers: socket 77.5%, serde_json 13.0%, jsonrpsee 3.9%, tokio 3.1%, plexus 2.4%, gate 0.2% · leaves: syscall:socket 77.5%, code 18.8%, alloc 3.1%, syscall:park 0.6%
