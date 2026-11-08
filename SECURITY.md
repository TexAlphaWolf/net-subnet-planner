# Security

## Model

subnetplan is a local tool. The web interface has **no authentication** and is meant for `127.0.0.1`; it prints a
warning when started on any other address. Treat anyone who can reach the port as an administrator of the database.

What it does to limit damage: strict Content-Security-Policy (`default-src 'self'`, no inline script), `nosniff`,
`no-referrer`, `no-store`; the page builds its DOM with `textContent`, never `innerHTML`; every field has a length and
range limit; static files are served from an allow-list; SQL is parameterised; errors do not carry stack traces.
The Docker image runs as an unprivileged user and works with a read-only root filesystem.

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab), not in a public issue.
