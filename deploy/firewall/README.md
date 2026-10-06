# Reference host firewall: no internet egress from the frontend network

**Example – review and adapt before use.** The `frontend` Docker network cannot be `internal: true`,
because published ports (Open WebUI on 3000, n8n editor and gateway on 127.0.0.1) live there.
Without a host firewall, every container on `frontend` (Open WebUI, n8n, Perplexica) can open
connections to the internet. These rules close that gap:

| Source bridge | Allowed | Dropped |
|---|---|---|
| `aism-frontend` | replies to inbound connections (published ports), traffic inside the bridge (UI ↔ gateway) | every new connection leaving the bridge (internet, other host networks) |
| `aism-backend` | traffic inside the bridge | anything leaving it (defence in depth; compose already sets `internal: true`) |
| `aism-egress` | everything (governance-proxy cloud egress under policy, SearXNG) | – (optional: only TCP 80/443, see comments) |

Containers on several networks (governance-proxy, SearXNG) must send internet traffic via the egress
bridge. `docker-compose.yml` therefore sets `gw_priority: 1` for their `egress` attachment
(Docker Engine ≥ 28.0; a community report confirms it working with Compose v2.35.1, while v2.33.1
validated but did not apply it – docker/compose#12574). Check inside the container with `ip route`
that the default route points to the egress network.

## Prerequisite: fixed bridge names

`docker-compose.yml` names the bridges via `driver_opts`:

```yaml
networks:
  frontend: { driver_opts: { com.docker.network.bridge.name: aism-frontend } }
  backend:  { internal: true, driver_opts: { com.docker.network.bridge.name: aism-backend } }
  egress:   { driver_opts: { com.docker.network.bridge.name: aism-egress } }
```

Existing networks keep their old bridge name: `docker compose down` and `up` again after the change.
Verify with `ip -br link | grep aism-`.

## Variant A: iptables `DOCKER-USER` (Docker's default firewall backend)

```bash
sudo ./docker-user.sh apply     # creates chain AISM-EGRESS and jumps to it from DOCKER-USER (idempotent)
sudo ./docker-user.sh show
sudo ./docker-user.sh remove
```

Docker recreates its own chains on restart but leaves `DOCKER-USER` alone; use the example unit
[`aism-egress-firewall.service`](aism-egress-firewall.service) to re-apply the rules after every Docker
start. Use the same iptables variant as the daemon (`IPTABLES=iptables-legacy` if Docker uses the
legacy backend). IPv6 rules are applied with `ip6tables` if present.

## Variant B: nftables (own table)

```bash
sudo nft -f aism-egress.nft                   # idempotent; table inet aism_egress
sudo nft list table inet aism_egress
sudo nft delete table inet aism_egress
```

The table hooks `forward` with priority `filter - 10`. A `drop` in any base chain is final, so it
works next to Docker's iptables-nft rules and next to Docker's native nftables backend. To make it
persistent, include the file from `/etc/nftables.conf` – **without** `flush ruleset`, which would
delete Docker's rules.

## How it was tested (05.10.2026)

### Real Docker host (Docker Engine 29.8.2, Compose v2, iptables-nft backend, IPv4 + IPv6)

The conformance stack (`docker-compose.yml` + `conformance/tests/compose.conformance.yml`
+ [`test/compose.ipv6.yml`](test/compose.ipv6.yml), dual-stack `frontend` `fd00:0:0:f::/64` and
`egress` `fd00:0:0:e::/64`) ran on a Debian host. "Outside" was a network namespace `ext`
(`10.99.0.2` / `fd00:beef::2`, TCP 8080) attached to the host via a veth pair, plus real internet
(`1.1.1.1:443`, IPv4 only – the host has no IPv6 uplink). A helper container `fw-probe-frontend`
sat on the frontend network only. [`test/probe.sh`](test/probe.sh) produced the matrix
(raw output: [`test/results-2026-10-05.txt`](test/results-2026-10-05.txt), re-recorded after the project was renamed to AISM, with identical results):

| From → to | without rules | Variant A (`docker-user.sh`, iptables-nft + ip6tables) | Variant B (`aism-egress.nft`) |
|---|---|---|---|
| frontend container → outside IPv4 | open | **blocked** | **blocked** |
| frontend container → outside IPv6 | open | **blocked** | **blocked** |
| frontend container → internet 1.1.1.1:443 | open | **blocked** | **blocked** |
| aism-mock (frontend + backend) → outside v4/v6/internet | open | **blocked** | **blocked** |
| frontend container → governance-proxy:8000 (same bridge) | open | open | open |
| governance-proxy → outside v4/v6/internet (default route via `egress`, `gw_priority: 1` works) | open | open | open |
| orchestrator (backend only, `internal: true`) → outside/internet | blocked | blocked | blocked |
| host → published `127.0.0.1:8000` | 200 | 200 | 200 |
| outside netns → port published on `0.0.0.0`, IPv4 and IPv6 (DNAT, replies) | 200 | 200 | 200 |

The nft counter of the frontend drop rule counted the blocked attempts (18 packets in one probe run).
The full conformance suite (37 tests) passed with Variant A active, so the rules do not break the
stack. Re-applying both variants is idempotent.

**Pitfall found:** the host had stale **iptables-legacy** rules from an earlier Docker install
(`FORWARD` policy `DROP` in the legacy table). The kernel evaluates legacy and nft tables both, so
all bridged traffic was dropped although `iptables-nft` looked clean. Check `iptables-legacy -S`
and `ip6tables-legacy -S` when containers cannot reach each other, and use only one backend.

**Not tested:** Docker's native nftables firewall backend (`"firewall-backend": "nftables"`,
experimental), real IPv6 internet, rootless Docker (its own network namespace; these rules do
not apply there).

### Earlier simulation (no Docker)

Before Docker was available the topology was rebuilt with Linux bridges and network namespaces
(Debian 13, nftables 1.1.3, iptables 1.8.11): frontend → internet blocked with both variants,
egress → internet and intra-bridge traffic open, re-apply idempotent.

## What this does not cover

- DNS: containers use Docker's embedded resolver (127.0.0.11), which resolves external names from
  the host namespace. Blocking egress does not stop name resolution; it stops connections.
- Host processes and containers with `network_mode: host` are not affected (the reference stack
  uses none).
- Inbound filtering of the host itself (`INPUT` chain, which published ports are reachable from
  where): bind published ports to `127.0.0.1` or a reverse proxy, as `docker-compose.yml` does,
  and use the host firewall of your distribution.
- Allowlisting specific cloud API hosts for the egress network (FQDN filtering) needs an egress
  proxy; IP-based rules are fragile for CDNs.
