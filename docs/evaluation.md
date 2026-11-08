# Evaluation

Produced by `python tools/evaluate.py` (full run) and stored in `report.json`. Correctness and fragmentation are
seeded, so they reproduce on any machine; timings are from the machine named in the report (Linux x86_64, Python 3.13)
and will differ on yours.

## 1. Correctness

Random cases checked against an independent reference. **20700 cases, 0 mismatches.**

| check | cases |
|---|---|
| `range_to_cidrs` vs `ipaddress.summarize_address_range` (IPv4 and IPv6) | 12000 |
| `summarize` vs `ipaddress.collapse_addresses`, and exact address coverage | 3000 |
| `free_blocks` vs an address bitmap, and minimality | 3000 |
| allocator: held and free blocks partition the parent after churn; a full release restores it | 300 |
| VLSM places everything if and only if the sizes fit; allocations never overlap | 1200 |
| `find_conflicts` vs the O(n²) definition | 1200 |

The pytest suite repeats these on smaller samples and adds the edge cases (/31, /32, /127, /128, host bits, hostile
input) plus the store, CLI and API.

## 2. Does the allocator waste space?

Churn on a /20 (1024 cells of /30), subnets from /24 to /30 weighted towards the small ones, 6000 operations per run,
15 runs per cell. Occupancy is held near the target by freeing a random subnet when above it. A refusal is **avoidable**
when the pool had enough free addresses in total but no aligned block big enough: fragmentation, not fullness.

| occupancy | buddy best-fit (subnetplan) | first-fit | next-fit |
|---|---|---|---|
| 60 % | 0.00 % | 0.00 % | 3.48 % |
| 75 % | 0.07 % | 0.10 % | 9.22 % |
| 90 % | 2.62 % | 3.69 % | 19.58 % |

Share of requests refused although the free space would have sufficed. At 90 % the buddy allocator had fewer avoidable
refusals than first-fit in 14 of the 15 runs (1 tie); at 75 % in 7 of 15 (2 ties); at 60 % there is no difference.

What this says: next-fit is clearly worse. Best-fit is better than first-fit only when the network is nearly full, and
by about one percentage point; do not expect more. What it does not say: real networks are not random, and a human
planning by hand may beat all three.

## 3. Speed

| | n | time |
|---|---|---|
| conflict detection, sweep (n log n) | 100000 | 0.31 s |
| | 500000 | 2.73 s |
| conflict detection, quadratic reference | 4000 | 14.19 s |
| VLSM plan | 50000 requests | 0.38 s |
| allocator alloc/release | 200000 operations | 219438 per second |

The quadratic version is the plain definition written for the tests, not an optimised competitor; it is here to show
the growth, not to claim a speed-up over other tools.
