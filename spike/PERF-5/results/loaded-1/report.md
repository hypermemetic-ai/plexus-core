## Calls (µs; medians of runs)

| src | label | scenario | rate | conns | inflight | p50 | p99 | p999 | calls/s | runs | load |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| plexus | rt=multi gate=on | call.one_item.seq |  |  |  | 96 | 948 | 2933 | 6,598 | 3 | 59.93 |
| plexus | rt=multi gate=on | call.one_item.open | 2000.0 | 1 |  | 161 | 3895 | 6578 | 2,000 | 3 | 59.93 |
| plexus | rt=multi gate=on | call.one_item.open | 5000.0 | 1 |  | 115 | 2632 | 3922 | 5,000 | 3 | 55.07 |
| plexus | rt=multi gate=on | call.one_item.open | 10000.0 | 1 |  | 505 | 21807 | 26575 | 9,990 | 3 | 53.79 |
| plexus | rt=multi gate=on | call.one_item.max |  | 1 | 1 | 119 | 2474 | 3910 | 4,537 | 3 | 54.28 |
| plexus | rt=multi gate=on | call.one_item.max |  | 1 | 16 | 882 | 4114 | 6873 | 14,415 | 3 | 52.10 |
| plexus | rt=multi gate=on | call.one_item.max |  | 64 | 1 | 1032 | 6390 | 12026 | 45,690 | 3 | 50.01 |
| plexus | rt=multi gate=on | call.one_item.max |  | 64 | 4 | 4157 | 13165 | 18711 | 54,302 | 3 | 49.88 |
| plexus | rt=multi gate=off | call.one_item.seq |  |  |  | 89 | 602 | 1794 | 8,923 | 3 | 47.41 |
| plexus | rt=multi gate=off | call.one_item.open | 2000.0 | 1 |  | 101 | 1048 | 2353 | 2,000 | 3 | 47.41 |
| plexus | rt=multi gate=off | call.one_item.open | 5000.0 | 1 |  | 76 | 1187 | 2621 | 5,000 | 3 | 44.49 |
| plexus | rt=multi gate=off | call.one_item.open | 10000.0 | 1 |  | 109 | 3682 | 5407 | 10,000 | 3 | 39.04 |
| plexus | rt=multi gate=off | call.one_item.max |  | 1 | 1 | 73 | 201 | 1776 | 11,147 | 3 | 37.35 |
| plexus | rt=multi gate=off | call.one_item.max |  | 1 | 16 | 569 | 1066 | 2603 | 27,006 | 3 | 36.52 |
| plexus | rt=multi gate=off | call.one_item.max |  | 64 | 1 | 843 | 3641 | 5497 | 67,842 | 3 | 34.80 |
| plexus | rt=multi gate=off | call.one_item.max |  | 64 | 4 | 2198 | 6525 | 10420 | 107,520 | 3 | 38.34 |
| plexus | rt=current gate=on | call.one_item.seq |  |  |  | 82 | 394 | 2000 | 10,758 | 3 | 40.55 |
| plexus | rt=current gate=on | call.one_item.open | 2000.0 | 1 |  | 99 | 2560 | 4119 | 2,000 | 3 | 38.43 |
| plexus | rt=current gate=on | call.one_item.open | 5000.0 | 1 |  | 98 | 2128 | 3062 | 5,000 | 3 | 37.83 |
| plexus | rt=current gate=on | call.one_item.open | 10000.0 | 1 |  | 87 | 2116 | 3553 | 10,000 | 3 | 36.48 |
| plexus | rt=current gate=on | call.one_item.max |  | 1 | 1 | 76 | 286 | 2004 | 11,179 | 3 | 33.03 |
| plexus | rt=current gate=on | call.one_item.max |  | 1 | 16 | 527 | 983 | 2007 | 27,698 | 3 | 31.34 |
| plexus | rt=current gate=on | call.one_item.max |  | 64 | 1 | 2324 | 3824 | 4665 | 25,950 | 3 | 30.19 |
| plexus | rt=current gate=on | call.one_item.max |  | 64 | 4 | 9535 | 13722 | 14729 | 26,006 | 3 | 29.22 |
| raw | raw fastwebsockets | call.one_item.seq |  |  |  | 47 | 204 | 1065 | 18,562 | 3 | 25.78 |
| raw | raw fastwebsockets | call.one_item.open | 10000.0 | 1 |  | 59 | 1027 | 2515 | 10,000 | 3 | 25.78 |
| raw | raw fastwebsockets | call.one_item.max |  | 1 | 16 | 375 | 680 | 1525 | 39,748 | 3 | 24.67 |
| raw | raw fastwebsockets | call.one_item.max |  | 64 | 4 | 1886 | 5579 | 10813 | 125,380 | 3 | 23.42 |
| raw | raw tungstenite | call.one_item.seq |  |  |  | 35 | 72 | 698 | 25,805 | 3 | 22.84 |
| raw | raw tungstenite | call.one_item.open | 10000.0 | 1 |  | 44 | 1211 | 2636 | 10,000 | 3 | 22.84 |
| raw | raw tungstenite | call.one_item.max |  | 1 | 16 | 185 | 310 | 1214 | 81,890 | 3 | 22.05 |
| raw | raw tungstenite | call.one_item.max |  | 64 | 4 | 1425 | 8823 | 16941 | 138,810 | 3 | 25.55 |

## Allocations and CPU per call

| run | allocs/call | bytes/call | spawned tasks/call | server CPU µs/call | vol cs/call |
| -- | -- | -- | -- | -- | -- |
| 0 | 105.00 | 11318 | 2.00 | 66.1 | 3.04 |
| 1 | 105.00 | 11318 | 2.00 | 66.4 | 3.06 |
| 2 | 105.00 | 11318 | 2.00 | 67.6 | 3.07 |

## Streams (10,000 items)

| src | label | size | items/s | allocs/item | alloc B/item | wire B/item | frames/item | server CPU µs/item | runs | load |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| plexus | rt=multi throughput | 64 | 101,124 | 0.00 | 0 | 340 | 1.000 | 6.06 | 3 | 28.40 |
| plexus | rt=multi throughput | 1024 | 93,682 | 0.00 | 0 | 1300 | 1.000 | 7.48 | 3 | 27.33 |
| plexus | rt=multi throughput | 4096 | 75,426 | 0.00 | 0 | 4372 | 1.000 | 11.50 | 3 | 27.33 |
| plexus | rt=current throughput | 64 | 129,919 | 0.00 | 0 | 340 | 1.000 | 5.00 | 3 | 27.33 |
| plexus | rt=current throughput | 4096 | 85,377 | 0.00 | 0 | 4372 | 1.000 | 8.41 | 3 | 27.33 |
| plexus | allocs | 64 | 115,187 | 17.02 | 1697 | 340 | 1.000 | 5.94 | 3 | 27.33 |
| plexus | allocs | 1024 | 97,050 | 19.02 | 6694 | 1300 | 1.000 | 7.16 | 3 | 27.33 |
| plexus | allocs | 4096 | 74,694 | 19.02 | 22054 | 4371 | 1.000 | 10.85 | 3 | 27.33 |
| raw | raw fastwebsockets | 64 | 108,625 | 0.00 | 0 | 344 | 1.000 | 5.52 | 3 | 23.87 |
| raw | raw fastwebsockets | 1024 | 93,213 | 0.00 | 0 | 1304 | 1.000 | 5.64 | 3 | 23.87 |
| raw | raw fastwebsockets | 4096 | 83,875 | 0.00 | 0 | 4376 | 1.000 | 7.82 | 3 | 22.84 |
| raw | raw tungstenite | 64 | 2,002,931 | 0.00 | 0 | 344 | 1.000 | 0.39 | 3 | 25.55 |
| raw | raw tungstenite | 1024 | 860,218 | 0.00 | 0 | 1304 | 1.000 | 1.05 | 3 | 25.55 |
| raw | raw tungstenite | 4096 | 153,553 | 0.00 | 0 | 4376 | 1.000 | 5.79 | 3 | 25.55 |

## Codecs (ns per item, median of 3 runs)

| frame | codec | op | bytes | ns | allocs |
| -- | -- | -- | -- | -- | -- |
| tickets.health | serde_json (today: event → Value → text) | encode | 220 | 541 | 12 |
| tickets.health | serde_json typed (one encode) | encode | 190 | 286 | 2 |
| tickets.health | serde_json → Value (today's clients) | decode | 220 | 1448 | 21 |
| tickets.health | serde_json typed | decode | 220 | 1732 | 12 |
| tickets.health | serde_json typed (struct) | decode | 190 | 1001 | 5 |
| tickets.health | sonic-rs typed (struct) | decode | 190 | 770 | 5 |
| tickets.health | sonic-rs → Value | decode | 220 | 419 | 4 |
| tickets.health | sonic-rs typed | encode | 190 | 243 | 3 |
| tickets.health | simd-json typed (struct, incl. the copy it mutates) | decode | 190 | 658 | 15 |
| tickets.health | simd-json → OwnedValue (incl. copy) | decode | 220 | 1472 | 35 |
| tickets.health | postcard | encode | 55 | 228 | 4 |
| tickets.health | postcard | decode | 55 | 298 | 5 |
| tickets.health | CBOR (ciborium) | encode | 152 | 187 | 1 |
| tickets.health | CBOR (ciborium) | decode | 152 | 832 | 5 |
| tickets.health | msgpack (rmp-serde, named) | encode | 152 | 242 | 6 |
| tickets.health | msgpack (rmp-serde, named) | decode | 152 | 261 | 5 |
| tickets.health | msgpack (rmp-serde, compact) | encode | 59 | 153 | 4 |
| tickets.health | msgpack (rmp-serde, compact) | decode | 59 | 290 | 5 |
| 1KB item | serde_json (today: event → Value → text) | encode | 1075 | 2079 | 13 |
| 1KB item | serde_json typed (one encode) | encode | 1047 | 909 | 4 |
| 1KB item | serde_json → Value (today's clients) | decode | 1075 | 2564 | 20 |
| 1KB item | serde_json typed | decode | 1075 | 2711 | 11 |
| 1KB item | serde_json typed (struct) | decode | 1047 | 1139 | 5 |
| 1KB item | sonic-rs typed (struct) | decode | 1047 | 895 | 5 |
| 1KB item | sonic-rs → Value | decode | 1075 | 563 | 3 |
| 1KB item | sonic-rs typed | encode | 1047 | 532 | 3 |
| 1KB item | simd-json typed (struct, incl. the copy it mutates) | decode | 1047 | 2371 | 13 |
| 1KB item | simd-json → OwnedValue (incl. copy) | decode | 1075 | 3063 | 32 |
| 1KB item | postcard | encode | 945 | 279 | 4 |
| 1KB item | postcard | decode | 945 | 315 | 5 |
| 1KB item | CBOR (ciborium) | encode | 1019 | 341 | 2 |
| 1KB item | CBOR (ciborium) | decode | 1019 | 1204 | 5 |
| 1KB item | msgpack (rmp-serde, named) | encode | 1019 | 589 | 6 |
| 1KB item | msgpack (rmp-serde, named) | decode | 1019 | 637 | 5 |
| 1KB item | msgpack (rmp-serde, compact) | encode | 950 | 417 | 5 |
| 1KB item | msgpack (rmp-serde, compact) | decode | 950 | 211 | 5 |
| summary row | serde_json (today: event → Value → text) | encode | 606 | 2976 | 51 |
| summary row | serde_json typed (one encode) | encode | 575 | 820 | 4 |
| summary row | serde_json → Value (today's clients) | decode | 606 | 3858 | 59 |
| summary row | serde_json typed | decode | 606 | 2890 | 50 |
| summary row | serde_json typed (struct) | decode | 575 | 2505 | 22 |
| summary row | sonic-rs typed (struct) | decode | 575 | 2235 | 22 |
| summary row | sonic-rs → Value | decode | 606 | 955 | 4 |
| summary row | sonic-rs typed | encode | 575 | 716 | 4 |
| summary row | simd-json typed (struct, incl. the copy it mutates) | decode | 575 | 1497 | 32 |
| summary row | simd-json → OwnedValue (incl. copy) | decode | 606 | 4683 | 75 |
| summary row | postcard | encode | 241 | 549 | 6 |
| summary row | postcard | decode | 241 | 1031 | 22 |
| summary row | CBOR (ciborium) | encode | 461 | 737 | 2 |
| summary row | CBOR (ciborium) | decode | 461 | 3450 | 22 |
| summary row | msgpack (rmp-serde, named) | encode | 463 | 1099 | 7 |
| summary row | msgpack (rmp-serde, named) | decode | 463 | 1986 | 22 |
| summary row | msgpack (rmp-serde, compact) | encode | 247 | 458 | 6 |
| summary row | msgpack (rmp-serde, compact) | decode | 247 | 1388 | 22 |

## In process

| group | bench | ns/op | allocs/op | bytes/op | runs |
| -- | -- | -- | -- | -- | -- |
| dispatch | block_on(empty) | 105 | 0.0 | 0 | 104/105/108 |
| dispatch | dispatch.echo_once (plain service, route → drain) | 1321 | 22.0 | 1288 | 967/1497/1321 |
| dispatch | dispatch.echo_once (gated service, signed in) | 1876 | 45.0 | 3489 | 1978/1876/1861 |
| dispatch | stream.1000 in process (plain), per call | 448139 | 10015.0 | 765440 | 448139/439134/961287 |
| gate | gate.check (Gate::check, repeated) | 562 | 20.0 | 2059 | 542/585/562 |
| frame | 1 · metadata.clone() + content_type.to_string() | 46 | 4.0 | 56 | 46/48/40 |
| frame | 2 · event → Value (serialize_with_credential_capture's to_value) | 152 | 6.0 | 708 | 151/152/214 |
| frame | 3 · item → RawValue (to_raw_value, the second encode) | 353 | 3.0 | 256 | 356/303/353 |
| frame | 4 · envelope: notification → String (jsonrpsee, copies the RawValue) | 232 | 3.0 | 668 | 232/206/251 |
| frame | 5 · ws frame: header + copy into the write buffer | 32 | 2.0 | 356 | 32/33/32 |
| frame | all five, as today | 724 | 17.0 | 2028 | 741/724/715 |
| frame | one encode into a reused frame buffer (the floor PERF-7 aims at) | 313 | 0.0 | 0 | 313/320/283 |
| boxing | 1000 items, generic stream | 1289 | 0.0 | 0 | 1405/1237/1289 |
| boxing | 1000 items, Pin<Box<dyn Stream>> (×2: the method's and wrap_stream's) | 3382 | 2.0 | 32 | 3389/3381/3382 |
| boxing | a boxed future per call (async_trait) | 10 | 1.0 | 1 | 10/10/11 |
| boxing | an unboxed future per call | 3 | 0.0 | 0 | 3/3/3 |
| tokio | tokio::spawn + join (current-thread), 1,000 in a row ÷ — per op ×1000 | 749824 | 1000.0 | 256000 | 773175/702633/749824 |
| tokio | mpsc hand-off task → task, 1,000 items (current-thread) | 54950 | 5.0 | 1632 | 55878/53789/54950 |
| tokio | tokio::spawn + join (multi-thread ×4), 1,000 in a row ÷ — per op ×1000 | 17973433 | 1000.0 | 256000 | 19011211/17973433/17319287 |
| tokio | mpsc hand-off task → task, 1,000 items (multi-thread ×4) | 280825 | 5.2 | 1686 | 280825/253683/283349 |

## CPU shares (SIGPROF samples, server process)
