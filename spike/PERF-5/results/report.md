## Calls (µs; medians of runs at ≤ 800 % other processes' CPU)

| src | label | scenario | rate | conns | inflight | p50 | p99 | p999 | calls/s | runs | load | others % |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| plexus | rt=multi gate=on | call.one_item.seq |  |  |  | 55 | 91 | 263 | 17,109 | 3 | 9.94 | 186–186 |
| plexus | rt=multi gate=on | call.one_item.open | 2000.0 | 1 |  | 70 | 229 | 582 | 2,000 | 3 | 9.94 | 186–186 |
| plexus | rt=multi gate=on | call.one_item.open | 5000.0 | 1 |  | 64 | 1192 | 2728 | 5,000 | 3 | 8.64 | 164–402 |
| plexus | rt=multi gate=on | call.one_item.open | 10000.0 | 1 |  | 58 | 1005 | 2863 | 10,000 | 3 | 8.19 | 316–402 |
| plexus | rt=multi gate=on | call.one_item.max |  | 1 | 1 | 56 | 89 | 421 | 16,776 | 3 | 7.85 | 316–316 |
| plexus | rt=multi gate=on | call.one_item.max |  | 1 | 16 | 505 | 890 | 2200 | 32,072 | 3 | 7.55 | 316–654 |
| plexus | rt=multi gate=on | call.one_item.max |  | 64 | 1 | 549 | 2173 | 4731 | 105,564 | 3 | 7.18 | 654–654 |
| plexus | rt=multi gate=off | call.one_item.seq |  |  |  | 51 | 73 | 94 | 18,934 | 3 | 6.78 | 229–229 |
| plexus | rt=multi gate=off | call.one_item.open | 2000.0 | 1 |  | 62 | 134 | 1226 | 2,000 | 3 | 6.32 | 229–424 |
| plexus | rt=multi gate=off | call.one_item.open | 5000.0 | 1 |  | 58 | 105 | 1501 | 5,000 | 1 | 6.05 | 424–424 |
| plexus | rt=current gate=on | call.one_item.seq |  |  |  | 54 | 119 | 224 | 16,515 | 3 | 7.20 | 264–264 |
| plexus | rt=current gate=on | call.one_item.open | 2000.0 | 1 |  | 69 | 102 | 633 | 2,000 | 3 | 7.20 | 230–264 |
| plexus | rt=current gate=on | call.one_item.open | 5000.0 | 1 |  | 63 | 97 | 120 | 5,000 | 3 | 6.33 | 147–376 |
| plexus | rt=current gate=on | call.one_item.open | 10000.0 | 1 |  | 53 | 658 | 2070 | 10,000 | 3 | 6.14 | 376–376 |
| plexus | rt=current gate=on | call.one_item.max |  | 1 | 1 | 54 | 74 | 100 | 17,541 | 3 | 5.97 | 703–703 |
| raw | raw fastwebsockets | call.one_item.seq |  |  |  | 37 | 45 | 54 | 26,375 | 3 | 6.39 | 300–300 |
| raw | raw fastwebsockets | call.one_item.open | 10000.0 | 1 |  | 42 | 979 | 2628 | 10,000 | 3 | 6.39 | 270–430 |
| raw | raw fastwebsockets | call.one_item.max |  | 1 | 16 | 372 | 552 | 610 | 41,923 | 3 | 5.88 | 430–477 |
| raw | raw fastwebsockets | call.one_item.max |  | 64 | 4 | 1638 | 4633 | 9724 | 142,742 | 1 | 7.17 | 477–477 |
| raw | raw tungstenite | call.one_item.open | 10000.0 | 1 |  | 31 | 215 | 1403 | 10,000 | 2 | 9.33 | 532–532 |
| raw | raw tungstenite | call.one_item.max |  | 1 | 16 | 155 | 260 | 314 | 99,804 | 3 | 8.82 | 274–324 |
| raw | raw tungstenite | call.one_item.max |  | 64 | 4 | 1225 | 5468 | 12272 | 192,153 | 3 | 13.40 | 479–479 |

### Busy: the same, from rows above 800 % (not in the medians above)

| src | label | scenario | rate | conns | inflight | p50 | p99 | p999 | calls/s | runs | load | others % |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| plexus | rt=multi gate=on | call.one_item.max |  | 64 | 4 | 2320 | 5591 | 7672 | 107,783 | 3 | 11.67 | 890–890 |
| plexus | rt=multi gate=off | call.one_item.open | 5000.0 | 1 |  | 77 | 2055 | 4387 | 5,000 | 2 | 6.05 | 1152–1152 |
| plexus | rt=multi gate=off | call.one_item.open | 10000.0 | 1 |  | 674 | 5435 | 7901 | 9,990 | 3 | 8.05 | 2263–2263 |
| plexus | rt=multi gate=off | call.one_item.max |  | 1 | 1 | 111 | 2976 | 4235 | 4,050 | 3 | 9.73 | 2137–2263 |
| plexus | rt=multi gate=off | call.one_item.max |  | 1 | 16 | 558 | 1165 | 3033 | 27,990 | 3 | 11.28 | 1335–2137 |
| plexus | rt=multi gate=off | call.one_item.max |  | 64 | 1 | 620 | 3076 | 6754 | 83,136 | 3 | 16.06 | 1160–1335 |
| plexus | rt=multi gate=off | call.one_item.max |  | 64 | 4 | 2206 | 5022 | 7533 | 112,542 | 3 | 20.14 | 807–807 |
| plexus | rt=current gate=on | call.one_item.max |  | 1 | 16 | 784 | 4477 | 6328 | 14,428 | 3 | 5.73 | 2110–2110 |
| plexus | rt=current gate=on | call.one_item.max |  | 64 | 1 | 2333 | 5480 | 6935 | 22,410 | 3 | 8.32 | 1542–2110 |
| plexus | rt=current gate=on | call.one_item.max |  | 64 | 4 | 10338 | 20234 | 32604 | 19,878 | 3 | 10.89 | 1806–1806 |
| raw | raw fastwebsockets | call.one_item.max |  | 64 | 4 | 1815 | 5063 | 9413 | 131,168 | 2 | 7.17 | 903–903 |
| raw | raw tungstenite | call.one_item.seq |  |  |  | 28 | 44 | 594 | 32,464 | 3 | 8.84 | 903–903 |
| raw | raw tungstenite | call.one_item.open | 10000.0 | 1 |  | 33 | 1292 | 2609 | 10,000 | 1 | 8.84 | 903–903 |

## Allocations and CPU per call

| run | allocs/call | bytes/call | spawned tasks/call | server CPU µs/call | vol cs/call |
| -- | -- | -- | -- | -- | -- |
| 0 | 105.00 | 11318 | 2.00 | 58.0 | 3.33 |
| 1 | 105.00 | 11318 | 2.00 | 56.4 | 3.18 |
| 2 | 105.00 | 11318 | 2.00 | 54.4 | 3.37 |

## Streams (10,000 items)

| src | label | size | items/s | allocs/item | alloc B/item | wire B/item | frames/item | server CPU µs/item | runs | load | others % |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| plexus | rt=multi throughput | 64 | 108,601 | 0.00 | 0 | 340 | 1.000 | 5.52 | 3 | 8.78 | 615–615 |
| plexus | rt=multi throughput | 1024 | 93,061 | 0.00 | 0 | 1300 | 1.000 | 7.30 | 3 | 8.78 | 615–615 |
| plexus | rt=multi throughput | 4096 | 72,569 | 0.00 | 0 | 4372 | 1.000 | 11.12 | 3 | 8.78 | 615–615 |
| plexus | rt=current throughput | 64 | 113,231 | 0.00 | 0 | 340 | 1.000 | 4.78 | 3 | 8.78 | 615–615 |
| plexus | rt=current throughput | 4096 | 80,688 | 0.00 | 0 | 4372 | 1.000 | 8.19 | 3 | 8.78 | 615–615 |
| plexus | allocs | 64 | 102,028 | 17.02 | 1696 | 340 | 1.000 | 5.14 | 3 | 8.78 | 615–615 |
| plexus | allocs | 1024 | 91,704 | 19.02 | 6694 | 1300 | 1.000 | 6.29 | 3 | 8.63 | 615–615 |
| plexus | allocs | 4096 | 81,429 | 19.02 | 22055 | 4372 | 1.000 | 8.69 | 3 | 8.63 | 615–615 |
| raw | raw tungstenite | 64 | 2,425,868 | 0.00 | 0 | 344 | 1.000 | 0.33 | 3 | 17.77 | 479–479 |
| raw | raw tungstenite | 1024 | 713,447 | 0.00 | 0 | 1304 | 1.000 | 1.29 | 3 | 17.77 | 479–479 |
| raw | raw tungstenite | 4096 | 218,297 | 0.00 | 0 | 4376 | 1.000 | 4.15 | 3 | 17.77 | 479–479 |
| raw, busy | raw fastwebsockets | 64 | 132,962 | 0.00 | 0 | 344 | 1.000 | 3.89 | 3 | 8.84 | 903–903 |
| raw, busy | raw fastwebsockets | 1024 | 114,697 | 0.00 | 0 | 1304 | 1.000 | 5.35 | 3 | 8.84 | 903–903 |
| raw, busy | raw fastwebsockets | 4096 | 87,183 | 0.00 | 0 | 4376 | 1.000 | 8.38 | 3 | 8.84 | 903–903 |

## Codecs (ns per item, median of 3 runs)

| frame | codec | op | bytes | ns | allocs | runs | load |
| -- | -- | -- | -- | -- | -- | -- | -- |
| tickets.health | serde_json (today: event → Value → text) | encode | 220 | 439 | 12 | 437/439/444 | 5.00 |
| tickets.health | serde_json typed (one encode) | encode | 190 | 212 | 2 | 206/217/212 | 4.76 |
| tickets.health | serde_json → Value (today's clients) | decode | 220 | 823 | 21 | 828/823/823 | 4.76 |
| tickets.health | serde_json typed | decode | 220 | 577 | 12 | 582/577/577 | 4.76 |
| tickets.health | serde_json typed (struct) | decode | 190 | 320 | 5 | 320/319/322 | 4.76 |
| tickets.health | sonic-rs typed (struct) | decode | 190 | 360 | 5 | 360/360/365 | 4.46 |
| tickets.health | sonic-rs → Value | decode | 220 | 231 | 4 | 231/232/231 | 4.46 |
| tickets.health | sonic-rs typed | encode | 190 | 186 | 3 | 186/186/186 | 4.46 |
| tickets.health | simd-json typed (struct, incl. the copy it mutates) | decode | 190 | 498 | 15 | 498/498/499 | 4.18 |
| tickets.health | simd-json → OwnedValue (incl. copy) | decode | 220 | 784 | 35 | 791/784/774 | 4.18 |
| tickets.health | postcard | encode | 55 | 154 | 4 | 153/154/155 | 4.18 |
| tickets.health | postcard | decode | 55 | 115 | 5 | 117/115/115 | 4.01 |
| tickets.health | CBOR (ciborium) | encode | 152 | 123 | 1 | 123/121/123 | 4.01 |
| tickets.health | CBOR (ciborium) | decode | 152 | 777 | 5 | 760/777/787 | 4.01 |
| tickets.health | msgpack (rmp-serde, named) | encode | 152 | 256 | 6 | 259/253/256 | 4.01 |
| tickets.health | msgpack (rmp-serde, named) | decode | 152 | 258 | 5 | 228/258/278 | 4.01 |
| tickets.health | msgpack (rmp-serde, compact) | encode | 59 | 149 | 4 | 148/149/149 | 4.01 |
| tickets.health | msgpack (rmp-serde, compact) | decode | 59 | 153 | 5 | 156/153/148 | 4.01 |
| 1KB item | serde_json (today: event → Value → text) | encode | 1075 | 858 | 13 | 858/872/854 | 4.01 |
| 1KB item | serde_json typed (one encode) | encode | 1047 | 638 | 4 | 638/636/641 | 3.93 |
| 1KB item | serde_json → Value (today's clients) | decode | 1075 | 873 | 20 | 873/863/873 | 3.93 |
| 1KB item | serde_json typed | decode | 1075 | 652 | 11 | 675/646/652 | 3.93 |
| 1KB item | serde_json typed (struct) | decode | 1047 | 449 | 5 | 449/453/444 | 3.85 |
| 1KB item | sonic-rs typed (struct) | decode | 1047 | 442 | 5 | 439/442/443 | 3.85 |
| 1KB item | sonic-rs → Value | decode | 1075 | 299 | 3 | 299/303/298 | 3.85 |
| 1KB item | sonic-rs typed | encode | 1047 | 228 | 3 | 226/228/228 | 3.78 |
| 1KB item | simd-json typed (struct, incl. the copy it mutates) | decode | 1047 | 780 | 13 | 780/798/763 | 3.78 |
| 1KB item | simd-json → OwnedValue (incl. copy) | decode | 1075 | 960 | 32 | 961/960/955 | 3.78 |
| 1KB item | postcard | encode | 945 | 140 | 4 | 140/140/140 | 3.78 |
| 1KB item | postcard | decode | 945 | 142 | 5 | 143/137/142 | 3.64 |
| 1KB item | CBOR (ciborium) | encode | 1019 | 176 | 2 | 176/178/175 | 3.64 |
| 1KB item | CBOR (ciborium) | decode | 1019 | 741 | 5 | 741/741/748 | 3.64 |
| 1KB item | msgpack (rmp-serde, named) | encode | 1019 | 270 | 6 | 270/278/263 | 3.51 |
| 1KB item | msgpack (rmp-serde, named) | decode | 1019 | 249 | 5 | 276/249/244 | 3.51 |
| 1KB item | msgpack (rmp-serde, compact) | encode | 950 | 191 | 5 | 191/191/198 | 3.51 |
| 1KB item | msgpack (rmp-serde, compact) | decode | 950 | 176 | 5 | 172/176/197 | 3.39 |
| summary row | serde_json (today: event → Value → text) | encode | 606 | 2352 | 51 | 2379/2341/2352 | 3.39 |
| summary row | serde_json typed (one encode) | encode | 575 | 640 | 4 | 640/629/640 | 3.39 |
| summary row | serde_json → Value (today's clients) | decode | 606 | 2984 | 59 | 2995/2951/2984 | 3.28 |
| summary row | serde_json typed | decode | 606 | 2596 | 50 | 2665/2596/2595 | 3.28 |
| summary row | serde_json typed (struct) | decode | 575 | 1185 | 22 | 1185/1172/1190 | 3.28 |
| summary row | sonic-rs typed (struct) | decode | 575 | 1207 | 22 | 1207/1207/1217 | 3.09 |
| summary row | sonic-rs → Value | decode | 606 | 435 | 4 | 435/435/437 | 3.09 |
| summary row | sonic-rs typed | encode | 575 | 524 | 4 | 543/515/524 | 3.09 |
| summary row | simd-json typed (struct, incl. the copy it mutates) | decode | 575 | 1240 | 32 | 1261/1240/1228 | 3.01 |
| summary row | simd-json → OwnedValue (incl. copy) | decode | 606 | 2155 | 75 | 2114/2155/2201 | 3.01 |
| summary row | postcard | encode | 241 | 289 | 6 | 291/286/289 | 3.01 |
| summary row | postcard | decode | 241 | 528 | 22 | 519/528/528 | 3.01 |
| summary row | CBOR (ciborium) | encode | 461 | 407 | 2 | 407/418/404 | 3.01 |
| summary row | CBOR (ciborium) | decode | 461 | 2604 | 22 | 2603/2604/2616 | 3.01 |
| summary row | msgpack (rmp-serde, named) | encode | 463 | 543 | 7 | 538/543/546 | 3.01 |
| summary row | msgpack (rmp-serde, named) | decode | 463 | 930 | 22 | 930/935/926 | 2.84 |
| summary row | msgpack (rmp-serde, compact) | encode | 247 | 362 | 6 | 362/362/363 | 2.84 |
| summary row | msgpack (rmp-serde, compact) | decode | 247 | 616 | 22 | 612/618/616 | 2.84 |

## In process

| group | bench | ns/op | allocs/op | bytes/op | runs | load |
| -- | -- | -- | -- | -- | -- | -- |
| dispatch | block_on(empty) | 88 | 0.0 | 0 | 88/88/88 | 5.84 |
| dispatch | dispatch.echo_once (plain service, route → drain) | 842 | 22.0 | 1288 | 841/842/842 | 5.84 |
| dispatch | dispatch.echo_once (gated service, signed in) | 1617 | 45.0 | 3489 | 1617/1622/1602 | 5.84 |
| dispatch | stream.1000 in process (plain), per call | 273514 | 10015.0 | 765440 | 273514/272268/276156 | 5.45 |
| gate | gate.check (Gate::check, repeated) | 483 | 20.0 | 2059 | 476/483/483 | 5.45 |
| frame | 1 · metadata.clone() + content_type.to_string() | 40 | 4.0 | 56 | 39/40/40 | 5.45 |
| frame | 2 · event → Value (serialize_with_credential_capture's to_value) | 141 | 6.0 | 708 | 141/143/140 | 6.06 |
| frame | 3 · item → RawValue (to_raw_value, the second encode) | 253 | 3.0 | 256 | 260/253/252 | 6.06 |
| frame | 4 · envelope: notification → String (jsonrpsee, copies the RawValue) | 176 | 3.0 | 668 | 176/176/178 | 6.06 |
| frame | 5 · ws frame: header + copy into the write buffer | 29 | 2.0 | 356 | 29/28/29 | 5.73 |
| frame | all five, as today | 665 | 17.0 | 2028 | 686/660/665 | 5.73 |
| frame | one encode into a reused frame buffer (the floor PERF-7 aims at) | 269 | 0.0 | 0 | 283/269/267 | 5.73 |
| boxing | 1000 items, generic stream | 1149 | 0.0 | 0 | 1149/1184/1134 | 5.35 |
| boxing | 1000 items, Pin<Box<dyn Stream>> (×2: the method's and wrap_stream's) | 3245 | 2.0 | 32 | 3247/3243/3245 | 5.35 |
| boxing | a boxed future per call (async_trait) | 10 | 1.0 | 1 | 10/10/10 | 5.35 |
| boxing | an unboxed future per call | 3 | 0.0 | 0 | 3/3/3 | 5.35 |
| tokio | tokio::spawn + join (current-thread), 1,000 in a row ÷ — per op ×1000 | 647210 | 1000.0 | 256000 | 652945/643783/647210 | 5.00 |
| tokio | mpsc hand-off task → task, 1,000 items (current-thread) | 48218 | 5.0 | 1632 | 48088/48310/48218 | 5.00 |
| tokio | tokio::spawn + join (multi-thread ×4), 1,000 in a row ÷ — per op ×1000 | 7302118 | 1000.0 | 256000 | 7084027/7302118/8279964 | 5.00 |
| tokio | mpsc hand-off task → task, 1,000 items (multi-thread ×4) | 120212 | 5.2 | 1683 | 122354/118834/120212 | 5.00 |

## menger on a throwaway (µs; medians of runs)

| label | p50 | p99 | p999 | max | calls/s | runs | load | others % |
| -- | -- | -- | -- | -- | -- | -- | -- | -- |
| menger, rust raw client | 67 | 93 | 108 | 212 | 14,358.8 | 3 | 10.44 | 110–110 |
| describe _info x | 157,155 | 162,398 | 162,398 | 162,398 | 6.3 | 3 | 10.44 | 110–110 |
| describe menger.hash x | 156,893 | 160,825 | 160,825 | 160,825 | 6.3 | 3 | 10.44–9.76 | 30–110 |
| describe menger.call tickets.schema | 238,158 | 244,842 | 244,842 | 244,842 | 4.1 | 3 | 9.06–9.76 | 31–31 |

## Syscalls per unit (strace -c -f in fedora:44, the server process, an idle run subtracted)

**call** — 2,000 units · **9.10 syscalls a unit** · futex 4.03, sendto 3.00, epoll_wait 1.07, recvfrom 1.00

**raw-fastwebsockets-stream64** — 30,000 units · **1.07 syscalls a unit** · sendto 1.00, mprotect 0.05, epoll_wait 0.01, write 0.01

**raw-tungstenite-stream64** — 30,000 units · **0.05 syscalls a unit** · mprotect 0.03, sendto 0.02

**stream4096** — 30,000 units · **1.30 syscalls a unit** · sendto 1.00, mprotect 0.18, futex 0.12

**stream64** — 30,000 units · **1.06 syscalls a unit** · sendto 1.00, futex 0.05, mprotect 0.01

## CPU shares (SIGPROF samples, server process)

**call** — 3159 samples · layers: socket 51.0%, tokio 22.7%, jsonrpsee 9.1%, serde_json 8.6%, plexus 4.9%, gate 3.7% · leaves: syscall:socket 51.0%, code 40.0%, syscall:park 6.8%, alloc 2.2%

**call64conns** — 4014 samples · layers: socket 32.4%, serde_json 23.2%, jsonrpsee 19.5%, plexus 10.6%, gate 8.3%, tokio 6.0% · leaves: code 58.0%, syscall:socket 32.4%, alloc 9.5%, syscall:park 0.1%

**stream4096** — 1204 samples · layers: socket 60.8%, serde_json 30.1%, jsonrpsee 5.7%, plexus 1.7%, tokio 1.2%, gate 0.4% · leaves: syscall:socket 60.8%, code 26.5%, alloc 12.5%, syscall:park 0.2%

**stream64** — 1776 samples · layers: socket 84.3%, serde_json 8.6%, jsonrpsee 3.2%, plexus 2.4%, tokio 1.4%, gate 0.1% · leaves: syscall:socket 84.3%, code 13.7%, alloc 1.8%, syscall:park 0.2%
