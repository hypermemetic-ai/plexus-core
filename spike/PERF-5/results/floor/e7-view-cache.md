### e7 — menger over the wire, signed in; medians over rows at ≤ 800 % others' CPU; gain against `base`

| call | `base` p50 · p99 ms | `PERF17_LINT_ONCE=1` p50 · p99 ms | `PERF17_DESCRIBE_CACHE=1` p50 · p99 ms | `PERF17_LINT_ONCE=1+PERF17_DESCRIBE_CACHE=1` p50 · p99 ms |
| -- | -- | -- | -- | -- |
| `_info x` | 158.859 · 230.031 [3] | 96.207 · 166.330 (2× faster) [3] | 0.060 · 0.146 (2,632× faster) [3] | 0.057 · 0.130 (2,773× faster) [3] |
| `menger.hash x` | 155.451 · 160.170 [3] | 93.520 · 98.435 (2× faster) [3] | 0.056 · 0.082 (2,797× faster) [3] | 0.058 · 0.087 (2,660× faster) [3] |
| `menger.call tickets.schema` | 237.371 · 250.216 [3] | 160.432 · 167.117 (1× faster) [3] | 17.613 · 39.027 (13× faster) [3] | 17.678 · 39.322 (13× faster) [3] |
| `menger.call tickets.health` | 0.067 · 0.092 [3] | 0.068 · 0.094 (-0.6 %) [3] | 0.066 · 0.094 (1× faster) [3] | 0.068 · 0.095 (-1.0 %) [3] |

others' CPU over the rows: 22–213 %; [n] = quiet runs in the median
