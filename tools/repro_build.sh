#!/bin/sh
# Build a local AISM image twice from scratch and compare the OCI manifest digests (see README,
# "Reproduzierbare Builds"). Usage: tools/repro_build.sh gateway|orchestrator [SOURCE_DATE_EPOCH]
# Needs docker buildx with a docker-container builder (the default "docker" driver cannot
# rewrite timestamps): docker buildx create --name aism-repro --driver docker-container
set -eu
svc=${1:?gateway|orchestrator}; sde=${2:-1791158400}; builder=${BUILDER:-aism-repro}
cd "$(dirname "$0")/.."
out=$(mktemp -d)
for i in 1 2; do
  docker buildx build --builder "$builder" --no-cache --provenance=false --sbom=false \
    --build-arg SOURCE_DATE_EPOCH="$sde" -f "$svc/Dockerfile" \
    --output "type=oci,dest=$out/$i.tar,rewrite-timestamp=true" . >/dev/null
  tar -xOf "$out/$i.tar" index.json | python3 -c "import json,sys;print(json.load(sys.stdin)['manifests'][0]['digest'])" > "$out/$i.digest"
done
d1=$(cat "$out/1.digest"); d2=$(cat "$out/2.digest")
echo "build 1: $d1"; echo "build 2: $d2"
if [ "$d1" = "$d2" ]; then echo "REPRODUCIBLE"; rm -rf "$out"; else echo "DIFFERENT (tars kept in $out)"; exit 1; fi
