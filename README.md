# Bloxy

A filtering proxy in Rust. It does four things:

- **Inspects and filters HTTPS** by terminating TLS with certificates minted by
  a local certificate authority, so requests inside an encrypted connection can
  be matched against filter rules.
- **Blackholes domains over DNS** with its own DNS server, fed by downloaded
  blocklists and by individually blocked domains.
- **Filters web traffic with uBlock Origin filter lists**, including both
  network rules and cosmetic (element-hiding) rules.
- **Ships a small web interface** — for administering all of the above.

## Building and running

```sh
cargo build --release
./target/release/bloxy --update-lists
```

On the first run bloxy creates a `data/` directory holding `config.json`, the
generated CA under `data/ca/`, and a cache of downloaded lists. The admin
password and API token hashes go in `data/admin-auth.json` once you set them
(see [Admin authentication](#admin-authentication)). `--update-lists`
downloads every enabled list; without it, bloxy starts from whatever is already
cached.

The defaults bind everything to loopback:

| Service          | Default address     |
| ---------------- | ------------------- |
| Proxy            | `127.0.0.1:8080`    |
| DNS              | `127.0.0.1:5353`    |
| Admin interface  | `127.0.0.1:8081`    |

Open <http://127.0.0.1:8081> to administer it. The interface asks for the admin
password, which you set once from the command line (see
[Admin authentication](#admin-authentication)). To serve other machines on the
network, change the listen addresses to `0.0.0.0` and turn on TLS for the admin
interface so the password and session cookie do not cross the network in clear.

Options:

```
--data-dir <DIR>        Config, CA, and list cache location (default: data)
--update-lists          Download every enabled list on startup
--log <FILTER>          tracing filter, e.g. "debug" or "bloxy::proxy=trace"
--set-admin-password    Prompt for a new admin password, store it, and exit
--new-api-token         Generate a new API token, print it once, and exit
```

## Admin authentication

The admin interface is locked until an admin password exists. Set one on the
server, then reload the page and sign in:

```sh
./target/release/bloxy --set-admin-password
```

It prompts twice without echo; when stdin is not a terminal it reads one line
instead, so `echo "$PW" | bloxy --set-admin-password` works in scripts. The
minimum is 8 characters. Only an Argon2id hash is stored, in
`data/admin-auth.json`. Signing in sets an `HttpOnly`, `SameSite=Strict`
session cookie. Sessions live in memory, expire after 24 hours idle, and do not
survive a restart. Five failed attempts from one address within 15 minutes lock
that address out until the window passes. The **Admin** tab has Sign out and a
change-password form; changing the password signs every other session out.

Scripts use a bearer token instead of a password. Generate one from the
**Admin** tab or from the command line:

```sh
./target/release/bloxy --new-api-token
```

The token is printed once and only its SHA-256 is kept, so copy it then. There
is one token at a time; generating a new one replaces the old one, and the Admin
tab can revoke it. The token works on every `/api/` route except credential
management and logout, which need a browser session:

```sh
curl -H "Authorization: Bearer bloxy_..." http://127.0.0.1:8081/api/status
```

Two settings on the **Admin** tab control the listener itself, and are also in
`config.json` under `admin`:

- `auth_required` (default `true`). Off, every request passes without
  credentials and the interface shows a warning banner. Leave it on unless the
  listener is on loopback and nobody else can reach the machine; bloxy logs a
  warning at startup when it is off on a non-loopback address.
- `tls_enabled` (default `false`) and `tls_hostname`. On, the admin listener
  serves HTTPS with a certificate minted by bloxy's own CA for `tls_hostname`,
  or for the listen IP when that is blank. The browser has to trust the CA
  (see [Trusting the CA](#trusting-the-ca)); `curl` needs
  `--cacert data/ca/bloxy-ca.crt`. The session cookie gains `Secure`. Changing
  either setting needs a restart.

## Trusting the CA

HTTPS interception only works once clients trust bloxy's CA. Download it from
the **Proxy & CA** tab, or straight from `http://127.0.0.1:8081/ca.crt`, then
compare the SHA-256 shown in the interface against the certificate you
installed before trusting it.

- **Windows**: `certutil -addstore -f Root bloxy-ca.crt` (as administrator).
- **macOS**: add to the System keychain and set it to *Always Trust*.
- **Linux**: copy to `/usr/local/share/ca-certificates/` and run
  `update-ca-certificates`.
- **Firefox** keeps its own store: Settings → Privacy & Security →
  Certificates → View Certificates → Authorities → Import.
- **Android/iOS** require installing it as a user CA, and recent Android
  versions no longer let apps trust user CAs by default.

The CA private key sits in `data/ca/bloxy-ca.key`. Anyone holding it can
impersonate any site to a machine that trusts the CA, so treat it as a secret
and generate a separate CA per deployment.

## Pointing clients at it

Set the proxy to `http://<host>:8080` for HTTP and HTTPS, and DNS to
`<host>:5353`. Using port 53 instead needs elevated privileges and a free port —
on desktop machines something is usually already bound to it.

The two halves work independently. DNS blocking alone stops connections from
being made at all, and is what protects devices that cannot use a proxy. Proxy
filtering alone gives per-URL and per-element precision. Running both means a
blocked domain is refused at whichever layer the client reaches first.

## How filtering works

**DNS.** Each query is checked against the merged blocklists. Blocking a domain
also blocks its subdomains; the allowlist overrides both blocklists and
individual blocks, and is checked at each level, so allowing
`cdn.example.com` leaves `example.com` blocked. Blocked names are answered
locally as `0.0.0.0` / `::`, NXDOMAIN, or REFUSED. Everything else is relayed
verbatim to an upstream resolver, which preserves record types and EDNS options
bloxy does not need to understand.

**Proxy.** Plain HTTP arrives as absolute-form requests. HTTPS arrives as
`CONNECT`: bloxy answers the tunnel itself with a minted certificate, then
filters the requests inside. Hosts on the bypass list, and every host when
interception is off, are relayed byte-for-byte — use the bypass list for apps
that pin certificates. Upstream certificates are always verified against the
webpki root store, so interception does not weaken the connection to the
origin. WebSocket upgrades are relayed through the tunnel.

Requests are matched against the filter lists using the resource type from
`Sec-Fetch-Dest`, falling back to `Accept` and the URL's file extension.
Blocked requests get a `403`. The admin interface records what was blocked and
which rule did it.

**Cosmetic filters.** With interception on, HTML responses are buffered,
decompressed, and have a `<style>` block of element-hiding selectors plus any
scriptlets spliced in right after `<head>`. gzip, deflate, brotli, and zstd are
all understood. Requests for documents advertise exactly that set, so an origin
cannot pick a coding that would push the page through unfiltered; other requests
are untouched and stream straight through.

Decompressed pages above 16 MB are served as they arrived rather than rewritten,
which caps what a compression bomb can cost.

## Configuration

`data/config.json` is written on first run and is fully editable from the web
interface. Editing it by hand works too, but bloxy only reads it at startup.

Most changes apply immediately: adding a domain, editing rules, or toggling a
list rebuilds the engines in the background while requests keep being served.
Changing a listen address, or enabling a service that was off, needs a restart —
the interface says so when you save.

## Limitations

- The admin interface has one admin identity: no users, roles, or external
  sign-in. Sessions are in memory, so a restart signs everyone out.
- The proxy speaks HTTP/1.1 only, and negotiates it via ALPN with both the
  client and the origin. HTTP/2 and HTTP/3 are not intercepted.
- QUIC is not handled at all, because a proxy is a TCP construct and HTTP/3 runs
  over UDP. Responses have their `Alt-Svc` header stripped so origins cannot
  steer clients onto an HTTP/3 endpoint, but a client can still discover one
  from a DNS `HTTPS`/`SVCB` record, which bloxy forwards untouched. Block
  UDP/443 if you need interception to be complete.
- Upstream DNS is plain UDP. There is no DNS-over-TLS or DNS-over-HTTPS.
- Responses using a content coding other than gzip, deflate, brotli, or zstd —
  or stacking several of them — pass through without cosmetic filtering.
- Procedural cosmetic filters (`:has-text()` and friends) are not applied.
- Clients that pin certificates will fail while intercepted. Add them to the
  bypass list.

## Layout

```
src/
  main.rs       startup, CLI, service supervision
  config.rs     configuration schema and on-disk layout
  state.rs      shared state; hot-swaps the engines on reload
  ca.rs         CA generation and per-host certificate minting
  dns.rs        DNS listeners, blackhole responses, upstream forwarding
  domains.rs    domain matching and hosts-file parsing
  filter.rs     uBlock Origin filter matching
  lists.rs      list downloads and caching
  auth/
    mod.rs      credentials file, password and token hashing, AuthState
    cli.rs      --set-admin-password and --new-api-token
    session.rs  in-memory session store, cookie parse and build
    lockout.rs  per-IP login failure tracker
  proxy/
    mod.rs      listener, CONNECT handling, request filtering
    upstream.rs origin connections and reuse
    rewrite.rs  cosmetic filter injection
  web/
    mod.rs      router assembly and static assets
    api.rs      admin JSON API
    auth_api.rs /api/auth/* handlers
    guard.rs    require_auth middleware
    serve.rs    accept loop, optional TLS
    assets/     index.html, style.css, app.js, panels.js, auth.js
```

Run the tests with `cargo test`.

#TODO:
- bug fixes
- TBD
