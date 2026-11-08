# Limitations

- **No authentication or multi-user control.** Keep the web interface on localhost or behind an authenticating proxy.
- **It records, it does not discover.** No scanning, no DHCP or DNS integration, no import from devices.
- **One writer at a time.** A single SQLite connection behind a lock: fine for a team's IPAM, not for heavy concurrent writes.
- **Allocation is power-of-two aligned**, as CIDR requires; a /26 is never carved from the middle of a /25 boundary. A
  request can be refused although enough addresses are free if they are scattered (see the fragmentation measurement).
- **Growth percentage** sizes a subnet for `hosts × (1 + growth)`; it is a planning aid, not a forecast. It is ignored
  for point-to-point links (always /31 or /127).
- **The web interface** cannot mark a request as a point-to-point link; use the CLI or the API (`"p2p": true`).
- **Limits on input**: 1000 requests per plan in the API, 100000 in the library, splits of at most 2^20 subnets.
- **The benchmark is synthetic**; see docs/evaluation.md for what it does and does not show.
