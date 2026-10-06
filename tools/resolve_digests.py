#!/usr/bin/env python3
"""Resolve image tags to registry digests (anonymous pull tokens, stdlib only).

Usage: python3 tools/resolve_digests.py ghcr.io/open-webui/open-webui:v0.11.4 qdrant/qdrant:v1.15.4 ...
Prints "<ref> <digest>" (digest of the manifest list / OCI index if the tag is multi-arch).
Never prints a digest it did not receive from the registry; failures are reported as ERROR.
"""
import json
import sys
import urllib.error
import urllib.request

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def split(ref):
    name, _, tag = ref.rpartition(":")
    if "/" in tag or not name:
        name, tag = ref, "latest"
    first = name.split("/")[0]
    if "." in first or ":" in first:
        registry, repo = first, name.split("/", 1)[1]
    else:
        registry, repo = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    return registry, repo, tag


def token(registry, repo):
    if registry == "registry-1.docker.io":
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    elif registry == "ghcr.io":
        url = f"https://ghcr.io/token?scope=repository:{repo}:pull"
    else:
        return None
    return json.load(urllib.request.urlopen(url, timeout=20))["token"]


def resolve(ref):
    registry, repo, tag = split(ref)
    req = urllib.request.Request(f"https://{registry}/v2/{repo}/manifests/{tag}", method="HEAD",
                                 headers={"Accept": ACCEPT})
    tok = token(registry, repo)
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=20) as r:
        d = r.headers.get("Docker-Content-Digest")
        if not d:
            raise RuntimeError("registry returned no Docker-Content-Digest header")
        return d


if __name__ == "__main__":
    rc = 0
    for ref in sys.argv[1:]:
        try:
            print(ref, resolve(ref), flush=True)
        except (urllib.error.URLError, RuntimeError, KeyError) as exc:
            print(ref, "ERROR", exc, flush=True)
            rc = 1
    sys.exit(rc)
