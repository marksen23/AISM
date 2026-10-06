#!/bin/sh
# Connectivity probes for the AISM host firewall on a real Docker host (see ../README.md, "Test").
# Needs: the conformance stack running (compose.conformance.yml [+ test/compose.ipv6.yml]),
# an "outside" network namespace with a listener (EXT4/EXT6), optionally real internet (NET4).
# Prints one line per probe: <from> -> <target> : open|blocked
set -u
EXT4=${EXT4:-10.99.0.2}; EXT6=${EXT6:-fd00:beef::2}; NET4=${NET4:-1.1.1.1}
DOCKER=${DOCKER:-docker}
probe() {  # container host port
  r=$($DOCKER exec "$1" python3 -c "
import socket,sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close(); print('open')
except OSError as e: print('blocked', type(e).__name__)" "$2" "$3" 2>&1)
  printf '%-26s -> %-24s : %s\n' "$1" "$2:$3" "$r"
}
for c in fw-probe-frontend aism-aism-mock-1; do      # frontend (aism-mock: frontend+backend)
  probe $c "$EXT4" 8080; probe $c "$EXT6" 8080; probe $c "$NET4" 443
done
probe fw-probe-frontend governance-proxy 8000          # intra-frontend must stay open
probe aism-governance-proxy-1 "$EXT4" 8080; probe aism-governance-proxy-1 "$EXT6" 8080; probe aism-governance-proxy-1 "$NET4" 443
probe aism-orchestrator-1 "$EXT4" 8080; probe aism-orchestrator-1 "$NET4" 443   # backend only
