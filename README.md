# Ghost

A small, rate-limited Cloudflare edge probe for network research from a phone
or any other host. It distinguishes TCP, TLS, and HTTP failures instead of
collapsing everything into “curl failed”.

The tool is deliberately **not** a mass scanner. It samples addresses from
Cloudflare's published ranges by default, and it has a hard probe cap.

## What it does

- Loads Cloudflare's official edge ranges from the API, a cache, or a built-in
  snapshot.
- Samples IPv4/IPv6 addresses from those prefixes.
- Dials a specific edge IP, uses your hostname as TLS SNI, sends one HTTP/1.1
  request, and records each phase separately.
- Parses `/cdn-cgi/trace` (`colo`, `warp`, `gateway`, `sni`, and friends).
- Recognises a Cloudflare Access login redirect.
- Adapts the connection rate downward on transport failures, `429`, or a
  challenge response.
- Writes JSONL records plus a human-readable summary.

## What it does not do

- It does not map an IP to a Cloudflare customer or Zero Trust app. Cloudflare
  is anycast; the hostname selects the zone.
- It does not enumerate a whole `/13` by default.
- It does not bypass Cloudflare bot management, Access, or carrier filtering.
- It does not use raw sockets, ICMP, or root-only features.

## The `104.18.x.x` question

Yes, `104.18.0.0/16` is part of Cloudflare's published `104.16.0.0/13`
block. But the default run does **not** walk `104.18.0.1`, `.2`, `.3`, and so
on.

Default behavior:

```bash
cfprobe -n 30
```

picks 30 random addresses across all selected prefixes. Each pick chooses a
random prefix, then a random address inside that prefix.

Three explicit alternatives:

```bash
# 10 random addresses from each selected prefix
cfprobe -per-cidr 10 -max 100

# every address in a small prefix, stopped by -max
cfprobe -cidr 104.18.0.0/24 -enumerate -max 256

# only the addresses the hostname resolves to
cfprobe -resolve -host app.example.com -path /
```

A `/13` has 524,288 IPv4 addresses. A `/24` has 256. If you really want a
small block enumerated, pass `-enumerate` and raise `-max` deliberately. The
code never silently turns into a full-range scan.

## Build

```bash
go build -o cfprobe ./cmd/cfprobe
go test ./...
```

On Termux:

```bash
pkg install golang ca-certificates git tmux
export SSL_CERT_FILE="$PREFIX/etc/tls/cert.pem"
go build -o cfprobe ./cmd/cfprobe
```

## Quick start

```bash
# See what would be probed, without opening any sockets
./cfprobe -ranges builtin -dry-run -n 20 -family all

# Baseline Cloudflare edge trace
./cfprobe -n 30 -conc 2 -rps 1 -timeout 8s -out results/run1.jsonl

# Test an Access-protected hostname without scanning ranges
./cfprobe -resolve -host app.example.com -path / -family all -max 10

# Probe 10 random addresses inside one specific block
./cfprobe -cidr 104.18.0.0/16 -per-cidr 10 -max 10

# Enumerate a single /24, slowly
./cfprobe -cidr 104.18.0.0/24 -enumerate -max 256 -conc 2 -rps 0.5
```

By default JSONL goes to stdout and the summary goes to stderr. Use
`-out results/run1.jsonl` to write records to a file, or `-summary=false` to
keep stderr quiet.

## Modes

| Mode | Flags | Behavior |
|---|---|---|
| Sample | `-n 30` | 30 random addresses, random prefix per pick |
| Per-prefix sample | `-per-cidr 10` | 10 random addresses from every selected prefix |
| Enumerate | `-enumerate -max 256` | every address in the selected prefixes, capped |
| Resolve | `-resolve -host example.com` | only the hostname's A/AAAA addresses |

`-resolve` is the right mode for “is my Zero Trust app reachable?” It does not
touch the range sampler. `-enumerate` is for small authorized blocks only.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-host` | `www.cloudflare.com` | TLS SNI and HTTP `Host` header |
| `-path` | `/cdn-cgi/trace` | request path |
| `-port` | `443` | TCP port |
| `-family` | `4` | `4`, `6`, or `all` |
| `-n` | `30` | total sampled addresses |
| `-per-cidr` | `0` | sampled addresses per prefix |
| `-enumerate` | `false` | walk selected prefixes |
| `-max` | `500` | hard probe cap |
| `-conc` | `2` | probes in flight |
| `-rps` | `1` | initial new probes per second |
| `-min-rps` | `0.2` | adaptive floor |
| `-max-rps` | `2` | adaptive ceiling |
| `-timeout` | `8s` | per-probe timeout |
| `-cooldown-every` | `25` | cool down every N probes; `0` disables |
| `-cooldown` | `5s` | base cool-down |
| `-seed` | now | reproducible samples |
| `-ranges` | `auto` | `auto`, `api`, `cache`, or `builtin` |
| `-cache` | platform cache | range cache path |
| `-refresh` | `false` | force an API refresh in auto mode |
| `-cidr` | none | CIDR to probe; repeatable/comma-separated |
| `-cidrs-file` | none | file of CIDRs, one per line |
| `-resolve` | `false` | resolve `-host` instead of sampling |
| `-dry-run` | `false` | print candidates and exit |
| `-out` | `-` | JSONL path, or `-` for stdout |
| `-summary` | `true` | print summary to stderr |
| `-version` | `false` | print version |

## Range sources

`-ranges auto` does this:

1. Use the cache if it is less than 30 days old.
2. Otherwise fetch `https://api.cloudflare.com/client/v4/ips`.
3. On failure, use the cache.
4. On failure, use the built-in snapshot.

`-ranges api` always fetches and updates the cache. `-ranges cache` never uses
the network. `-ranges builtin` never uses the network or cache.

The official ranges are also published at:

- `https://www.cloudflare.com/ips-v4`
- `https://www.cloudflare.com/ips-v6`

## Output

Each JSONL line is one probe. Important fields:

| Field | Meaning |
|---|---|
| `stage` | `tcp`, `tls`, `http-write`, `http-read`, or `http` |
| `reachable` | any HTTP response was received |
| `http_ok` | status is 2xx or 3xx |
| `trace_ok` | 200 + `cf-ray` + a `/cdn-cgi/trace` body |
| `ok` | `trace_ok` or a Cloudflare Access redirect |
| `status` | HTTP status, if one was received |
| `error_kind` | stable transport/status label |
| `tcp_ms`, `tls_ms`, `ttfb_ms`, `total_ms` | phase timings |
| `cf_ray` | Cloudflare request ID |
| `cf_mitigated` | challenge/WAF marker, if present |
| `location` | redirect target |
| `access_redirect` | redirect points at `cloudflareaccess.com` |
| `trace` | parsed `/cdn-cgi/trace` key/value map |

Summary example:

```text
total=30 reachable=28 http_ok=27 ok=28 failed=2 ok_rate=93.3%
stage: http=28 tcp=2
status: 200=27 302=1
error: tcp_deadline=2
colo: AMS=13 FRA=15
family: 4=30
tcp_ms p50=31 p95=78
tls_ms p50=52 p95=110
ttfb_ms p50=61 p95=130
```

## Interpreting failures

| Result | Likely meaning |
|---|---|
| `tcp_deadline`, `tcp_timeout` | Carrier/network drop or blackhole |
| `tcp_refused` | Port closed or service not listening |
| `tcp_unreachable`, `tcp_no_route` | No route, often IPv6 |
| `tls_reset`, `tls_eof` | DPI/SNI filtering or an edge reset |
| `tls_cert`, `tls_hostname`, `tls_unknown_authority` | Captive portal, MITM, or wrong SNI |
| `http_429` | Rate limit; back off and respect `Retry-After` |
| `cf_mitigated` | Cloudflare challenge/WAF policy |
| `status=302`, `access_redirect=true` | Network works; Zero Trust login is next |
| `trace_ok=true` | Cloudflare edge and zone answered |

A successful TCP/TLS handshake does not prove the app works. A `302` to
`cloudflareaccess.com` is the normal unauthenticated Access response. A `200`
may mean unprotected or authenticated.

## Mobile / Termux notes

Cellular networks add CGNAT, NAT session limits, DPI, radio wakeups, and
Android Doze. Keep the defaults low:

- 2 concurrent probes, 1 new connection per second, 30 samples
- cool down every 25 probes
- stop and back off on repeated resets or `429`
- test IPv4 and IPv6 separately
- use `termux-wake-lock` and a `tmux` session for long runs
- allow unrestricted mobile data for Termux and disable battery optimization

Check whether a VPN/Private DNS is intercepting traffic:

```bash
curl -sS https://www.cloudflare.com/cdn-cgi/trace | grep -E 'warp|gateway|colo'
```

No root is needed for TCP/TLS/HTTP/UDP. Root is only relevant for raw sockets,
ICMP, `iptables`, and binding sockets to a specific interface. To force
cellular, turn Wi-Fi off.

## Design notes

- The probe intentionally uses HTTP/1.1 over a manually established TLS
  connection. That keeps TCP, TLS, and HTTP failures unambiguous. HTTP/2 can be
  added later with `http.Transport` and `ForceAttemptHTTP2`.
- The certificate is verified by default. The tool has no insecure mode; a
  certificate failure is a real finding (often a captive portal).
- The rate limiter counts new connections, not HTTP requests.
- On CGNAT you share a public IP with other subscribers. Aggressive probing can
  get that shared address challenged, so keep volume tiny.
- `-max` is a guardrail, not a challenge. Raise it only for an authorized
  experiment.

## Development

```bash
make fmt
make vet
make test
make build
```

Layout:

```text
cmd/cfprobe/             CLI
internal/cloudflare/     official ranges, cache, fallback snapshot
internal/sampler/        random sampling and bounded enumeration
internal/probe/          one TCP/TLS/HTTP probe
internal/runner/         worker pool, limiter, adaptive controller
internal/report/         JSONL and summary
```

## Legal

Only probe IP ranges and hostnames you own or have permission to test. Respect
Cloudflare's terms and your carrier's terms. For broad censorship or
reachability research, use distributed measurement platforms such as OONI
Probe or RIPE Atlas rather than scanning from one mobile line.
