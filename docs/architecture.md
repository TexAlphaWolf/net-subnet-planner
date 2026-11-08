# Architecture

```text
 cli.py ──┐                       ┌── web/ (index.html, app.js, style.css)
          ├── netmath.py (pure)   │
 api.py ──┤                       │
          └── store.py (SQLite) ──┘
```

- **netmath.py**: pure functions and the allocator, no I/O. Everything else is a thin layer over it.
  - `Pool`: free space as aligned power-of-two blocks; allocation takes the smallest block that fits (lowest address among
    equals), splitting it; release merges with the buddy.
  - `vlsm`: largest first. Sizes are powers of two, so packing largest-first leaves no avoidable gap.
  - `find_conflicts`: one sweep over prefixes sorted by address with a stack, O(n log n). CIDR blocks never overlap
    partially, so the only conflicts are "duplicate" and "nested".
  - Usable hosts: IPv4 minus network and broadcast, except /31 (RFC 3021) and /32; IPv6 is the full size.
- **store.py**: SQLite. Addresses are stored as fixed-width big-endian BLOBs (4 or 16 bytes), so SQLite's byte-wise order
  equals numeric order and range queries work for IPv6 too. Writes run in `BEGIN IMMEDIATE` transactions; a plan is saved
  all or nothing. Schema version is stored and checked.
- **api.py**: FastAPI, one SQLite connection serialised by a lock, pydantic limits on every field, security headers on
  every response, static files from an allow-list.
- **cli.py**: argparse; `--json` everywhere; exit codes 0/1/2.
