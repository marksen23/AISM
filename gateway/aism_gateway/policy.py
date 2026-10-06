"""Policy loading: JSON-Schema validation, semantic checks, digest (Policy-Format §4, §6)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any

import jsonschema
import yaml

from . import keyring as trust
from . import policysig


class PolicyError(Exception):
    pass


@dataclass
class Policy:
    raw: dict
    digest: str
    path: str
    mtime: float
    rules_sorted: list[dict] = field(default_factory=list)
    signature: dict = field(default_factory=lambda: {"verified": False})

    @property
    def meta(self) -> dict:
        return self.raw["metadata"]

    @property
    def spec(self) -> dict:
        return self.raw["spec"]

    def info(self) -> dict:
        m = self.meta
        return {"name": m["name"], "version": m["version"], "revision": m.get("revision"), "digest": self.digest,
                "signature_verified": bool(self.signature.get("verified")),
                "signers": list(self.signature.get("signers") or [])}

    # ── lookups ──────────────────────────────────────────────────────
    def providers(self) -> list[dict]:
        return self.spec["routing"]["providers"]

    def provider(self, pid: str) -> dict | None:
        return next((p for p in self.providers() if p["id"] == pid), None)

    def provider_for_model(self, model: str) -> dict | None:
        return next((p for p in self.providers() if model in p["models"]), None)

    def data_class_rank(self, dc: str) -> int:
        return next(c["rank"] for c in self.spec["dataClasses"] if c["id"] == dc)

    def tool(self, name: str) -> dict | None:
        return next((t for t in self.spec["tools"]["definitions"] if t["id"] == name), None)


def _semantic_checks(p: dict) -> list[str]:
    errs: list[str] = []
    spec = p["spec"]

    def dup(ids, what):
        seen = set()
        for i in ids:
            if i in seen:
                errs.append(f"doppelte {what}-ID: {i}")
            seen.add(i)

    roles = [r["id"] for r in spec["subjects"]["roles"]]
    agents = [a["id"] for a in spec["subjects"].get("agents", [])]
    dcs = [c["id"] for c in spec["dataClasses"]]
    provs = [x["id"] for x in spec["routing"]["providers"]]
    dup(roles, "Rollen"); dup(dcs, "Datenklassen"); dup(provs, "Provider")
    dup([d["id"] for d in spec["piiDetectors"]], "Detektor")
    dup([t["id"] for t in spec["tools"]["definitions"]], "Tool")
    dup([r["id"] for r in spec["routing"]["rules"]], "Regel")

    for d in spec["piiDetectors"]:
        for pat in d.get("patterns", []):
            try:
                re.compile(pat)
            except re.error as exc:
                errs.append(f"Detektor {d['id']}: Regex ungültig ({exc})")
        if d["type"] == "gazetteer":
            g = d.get("gazetteer") or {}
            for key in ("givenNames", "surnames"):
                ref = str(g.get(key, ""))
                rel = ref[5:] if ref.startswith("file:") else ""
                if ref.startswith("builtin:"):
                    if ref not in ("builtin:de-given", "builtin:de-surnames"):
                        errs.append(f"Detektor {d['id']}: unbekanntes Gazetteer {ref}")
                elif ref.startswith("file:"):
                    if not rel or rel.startswith(("/", "\\")) or ".." in pathlib.PurePosixPath(rel.replace("\\", "/")).parts:
                        errs.append(f"Detektor {d['id']}: file:-Pfad ungültig ({ref})")
                else:
                    errs.append(f"Detektor {d['id']}: Gazetteer-Referenz {ref!r} muss builtin: oder file: sein")
            if g.get("contextPreset", "de") not in ("de", "none"):
                errs.append(f"Detektor {d['id']}: contextPreset {g.get('contextPreset')!r} ist unbekannt")
            for rule in g.get("contextRules") or []:
                if rule.get("accept") not in ("cue", "gazetteer-all", "gazetteer-any"):
                    errs.append(f"Detektor {d['id']}: accept {rule.get('accept')!r} ist unbekannt")
                for pat in rule.get("patterns") or []:
                    try:
                        cre = re.compile(pat)
                    except re.error as exc:
                        errs.append(f"Detektor {d['id']}: Kontextmuster ungültig ({exc})")
                        continue
                    if "pii" not in cre.groupindex:
                        errs.append(f"Detektor {d['id']}: Kontextmuster ohne Gruppe (?P<pii>…)")
        for r in d["masking"].get("demaskFor", []):
            if r not in roles:
                errs.append(f"Detektor {d['id']}: unbekannte Rolle {r}")
        ner = d.get("ner") or {}
        cascade = ner.get("cascade")
        if cascade is not None:
            if d["type"] != "ner":
                errs.append(f"Detektor {d['id']}: ner.cascade ist nur bei type ner zulässig")
            model = str(cascade.get("model") or "")
            if not re.fullmatch(r"(spacy|gliner):\S+", model):
                errs.append(f"Detektor {d['id']}: Kaskaden-Modell {model!r} muss 'spacy:<modell>' oder 'gliner:<modell>' sein")
            if not cascade.get("labels"):
                errs.append(f"Detektor {d['id']}: ner.cascade.labels fehlt")

    prov_type = {x["id"]: x["type"] for x in spec["routing"]["providers"]}
    prio_seen: dict[int, str] = {}
    for rule in spec["routing"]["rules"]:
        w, rt = rule["when"], rule["route"]
        for r in w.get("roles", []):
            if r not in roles:
                errs.append(f"Regel {rule['id']}: unbekannte Rolle {r}")
        for dc in w.get("dataClasses", []):
            if dc not in dcs:
                errs.append(f"Regel {rule['id']}: unbekannte Datenklasse {dc}")
        for pid in rt.get("localProviders", []):
            if prov_type.get(pid) != "local":
                errs.append(f"Regel {rule['id']}: {pid} ist kein lokaler Provider")
        for pid in rt.get("cloudProviders", []):
            if prov_type.get(pid) != "cloud":
                errs.append(f"Regel {rule['id']}: {pid} ist kein Cloud-Provider")
        if rule["priority"] in prio_seen:
            errs.append(f"Regeln {prio_seen[rule['priority']]} und {rule['id']} haben dieselbe Priorität")
        prio_seen[rule["priority"]] = rule["id"]

    for t in spec["tools"]["definitions"]:
        for r in t["allow"]["roles"]:
            if r not in roles:
                errs.append(f"Tool {t['id']}: unbekannte Rolle {r}")
        for a in t["allow"].get("agents", []):
            if a not in agents:
                errs.append(f"Tool {t['id']}: unbekannter Agent {a}")
        try:
            jsonschema.Draft202012Validator.check_schema(t["argumentsSchema"])
        except jsonschema.SchemaError as exc:
            errs.append(f"Tool {t['id']}: argumentsSchema ungültig ({exc.message})")
    for c in spec["rag"]["collections"]:
        for r in c["allow"]["roles"]:
            if r not in roles:
                errs.append(f"Collection {c['id']}: unbekannte Rolle {r}")

    audit = spec.get("audit") or {}
    seen_sinks: set[str] = set()
    required_worm = False
    for sink in audit.get("sinks") or []:
        sid = str(sink.get("id"))
        if sid in seen_sinks:
            errs.append(f"doppelte Audit-Senke: {sid}")
        seen_sinks.add(sid)
        if sink.get("type") == "s3-object-lock":
            endpoint = str(sink.get("endpoint") or "")
            if not endpoint.startswith(("http://", "https://")):
                errs.append(f"Senke {sid}: endpoint muss http:// oder https:// sein")
            prefix = str(sink.get("prefix") or "")
            if prefix.startswith("/") or ".." in prefix.replace("\\", "/").split("/"):
                errs.append(f"Senke {sid}: prefix ungültig")
            mode = str(sink.get("lockMode") or "compliance").lower()
            if audit.get("failClosed") and sink.get("required", True):
                if mode != "compliance":
                    errs.append(f"Senke {sid}: failClosed verlangt lockMode compliance")
                else:
                    required_worm = True
        elif sink.get("type") == "syslog":
            endpoint = str(sink.get("endpoint") or "")
            if not endpoint.startswith(("tcp://", "udp://")):
                errs.append(f"Senke {sid}: syslog endpoint muss tcp:// oder udp:// sein")
    if audit.get("failClosed") and not required_worm:
        errs.append("audit.failClosed verlangt eine required s3-object-lock-Senke im Compliance-Modus")
    algorithm = (audit.get("integrity") or {}).get("algorithm")
    if algorithm not in (None, "sha256"):
        errs.append("das Referenz-Gateway verkettet Audit-Einträge nur mit sha256")
    return errs


@dataclass
class SignatureConfig:
    """Gateway-side trust configuration (NOT part of the policy, so a policy cannot weaken it)."""
    required: bool = False
    allowed_signers: str | None = None   # path to an OpenSSH allowed_signers file (single-signature deployments)
    keyring: trust.KeyringDoc | None = None
    now: dt.datetime | None = None


def _signature_block(raw: dict) -> tuple[dict, dict]:
    meta = raw.get("metadata") if isinstance(raw, dict) else None
    sig = (meta or {}).get("signature") if isinstance(meta, dict) else None
    return meta if isinstance(meta, dict) else {}, sig if isinstance(sig, dict) else {}


def _require_shape(meta: dict, sig: dict, sc: SignatureConfig) -> str:
    if not isinstance(sig, dict) or not sig:
        raise PolicyError("Signatur erforderlich, aber metadata.signature fehlt (unsignierte Policy abgelehnt)")
    if sig.get("method") != "ssh-sig":
        raise PolicyError(f"Signaturmethode {sig.get('method')!r} wird vom Gateway nicht verifiziert (erwartet ssh-sig)")
    if not meta.get("revision"):
        raise PolicyError("signierte Policy ohne metadata.revision abgelehnt")
    ref = str(sig.get("ref", ""))
    if not ref or "/" in ref or "\\" in ref or ref.startswith("."):
        raise PolicyError("metadata.signature.ref muss ein Dateiname im Policy-Verzeichnis sein")
    if sc.keyring is None and not sc.allowed_signers:
        raise PolicyError("Signatur erforderlich, aber kein Vertrauensanker (POLICY_KEYRING oder POLICY_ALLOWED_SIGNERS) konfiguriert")
    return ref


def _result(sc: SignatureConfig, verification: trust.PolicyVerification, ref: str, doc: trust.KeyringDoc) -> dict:
    return {"verified": True, "required": sc.required, "method": "ssh-sig", "signers": list(verification.signers),
            "threshold": verification.threshold, "fingerprints": verification.fingerprints,
            "namespace": verification.namespace, "keyring_version": doc.version, "keyring_digest": doc.digest,
            "ref": ref}


def _check_with_keyring(meta: dict, sig: dict, data: bytes, path: pathlib.Path, sc: SignatureConfig) -> dict:
    ref = _require_shape(meta, sig, sc)
    doc = sc.keyring
    assert doc is not None
    try:
        payload = (path.parent / ref).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"Signatur nicht lesbar: {exc}") from exc
    revision = str(meta["revision"])
    raw_th = sig.get("threshold")
    meta_th = int(raw_th) if raw_th is not None else None
    try:
        if ref.endswith(".sigs"):
            bundle = payload
        else:
            bundle = trust.single_sig_bundle(data, payload, str(sig.get("signer") or ""), revision)
        verification = trust.verify_policy(data, bundle, doc, revision, meta_th, sc.now)
    except (trust.KeyringError, policysig.SignatureError, ValueError) as exc:
        raise PolicyError(f"Signaturprüfung fehlgeschlagen: {exc}") from exc
    return _result(sc, verification, ref, doc)


def _check_signature(raw: dict, data: bytes, path: pathlib.Path, sc: SignatureConfig) -> dict:
    meta, sig = _signature_block(raw)
    anchored = bool(sc.allowed_signers) or sc.keyring is not None
    if not sc.required and not (anchored and sig):
        return {"verified": False, "required": False}
    if sc.keyring is not None:
        return _check_with_keyring(meta, sig, data, path, sc)
    ref = _require_shape(meta, sig, sc)
    try:
        anchors = pathlib.Path(sc.allowed_signers or "").read_text(encoding="utf-8")
        armored = (path.parent / ref).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"Signatur/Vertrauensanker nicht lesbar: {exc}") from exc
    try:
        info = policysig.verify(data, armored, anchors, sig.get("signer"))
    except policysig.SignatureError as exc:
        raise PolicyError(f"Signaturprüfung fehlgeschlagen: {exc}") from exc
    return {"verified": True, "required": sc.required, "method": "ssh-sig", "signer": info.principal,
            "signers": [info.principal], "threshold": 1, "key_fingerprint": info.key_fingerprint,
            "fingerprints": {info.principal: info.key_fingerprint}, "namespace": info.namespace, "ref": ref}


def load_policy(path: str | pathlib.Path, schema_path: str | pathlib.Path,
                sig: SignatureConfig | None = None, current: "Policy | None" = None) -> Policy:
    path = pathlib.Path(path)
    sig = sig or SignatureConfig()
    try:
        data = path.read_bytes()
        mtime = path.stat().st_mtime
    except OSError as exc:
        raise PolicyError(f"Policy nicht lesbar: {exc}") from exc
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Policy ist kein gültiges YAML: {exc}") from exc
    # signature first: an unsigned/tampered file is rejected before its content is interpreted
    sig_info = _check_signature(raw, data, path, sig)
    schema = json.loads(pathlib.Path(schema_path).read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(raw), key=lambda e: e.json_path)
    if errors:
        raise PolicyError("Schemafehler: " + "; ".join(f"{e.json_path}: {e.message}" for e in errors[:10]))
    sem = _semantic_checks(raw)
    if sem:
        raise PolicyError("Semantische Fehler: " + "; ".join(sem))
    if current is not None and sig_info.get("verified"):
        # anti-rollback: a validly signed but older policy (earlier effectiveFrom) is not activated
        old, new = current.meta.get("effectiveFrom"), raw["metadata"].get("effectiveFrom")
        if old and new and _ts(new) < _ts(old):
            raise PolicyError(f"Rollback abgelehnt: effectiveFrom {new} liegt vor der aktiven Policy ({old})")
    pol = Policy(raw=raw, digest="sha256:" + hashlib.sha256(data).hexdigest(), path=str(path), mtime=mtime)
    pol.rules_sorted = sorted(raw["spec"]["routing"]["rules"], key=lambda r: -r["priority"])
    pol.signature = sig_info
    return pol


def _ts(v) -> float:
    import datetime as dt
    if isinstance(v, dt.datetime):
        return v.timestamp()
    return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()


# ── evaluation helpers (Policy-Format §5) ────────────────────────────

def roles_for_claims(policy: Policy, claims: dict[str, Any]) -> list[str]:
    out = []
    for r in policy.spec["subjects"]["roles"]:
        val = claims.get(r["match"]["claim"])
        vals = val if isinstance(val, list) else ([val] if val is not None else [])
        if any(str(v) in r["match"]["anyOf"] for v in vals):
            out.append(r["id"])
    return out


def data_class(policy: Policy, entities: set[str], roles: list[str], collections: list[str] | None = None) -> str:
    best, best_rank = None, -1
    for c in policy.spec["dataClasses"]:
        aw = c.get("assignWhen") or {}
        hit = (aw.get("always") is True
               or bool(set(aw.get("detectedEntities", [])) & entities)
               or bool(set(aw.get("roles", [])) & set(roles))
               or bool(set(aw.get("collections", [])) & set(collections or [])))
        if hit and c["rank"] > best_rank:
            best, best_rank = c["id"], c["rank"]
    return best or min(policy.spec["dataClasses"], key=lambda c: c["rank"])["id"]


def match_route(policy: Policy, dc: str, roles: list[str], agent: str | None, model: str) -> tuple[dict | None, list[dict]]:
    """First match by descending priority. Returns (rule or None, trace)."""
    trace = []
    for rule in policy.rules_sorted:
        w = rule["when"]
        reasons = []
        if "dataClasses" in w and dc not in w["dataClasses"]:
            reasons.append("data_class")
        if "roles" in w and not set(w["roles"]) & set(roles):
            reasons.append("roles")
        if "agents" in w and agent not in w["agents"]:
            reasons.append("agent")
        if "models" in w and model not in w["models"]:
            reasons.append("model")
        trace.append({"rule": rule["id"], "priority": rule["priority"], "matched": not reasons,
                      **({"reason": ",".join(reasons)} if reasons else {})})
        if not reasons:
            return rule, trace
    return None, trace


def allowed_tools(policy: Policy, roles: list[str], agent: str | None, dc_rank: int) -> list[str]:
    out = []
    for t in policy.spec["tools"]["definitions"]:
        a = t["allow"]
        if not set(a["roles"]) & set(roles):
            continue
        if a.get("agents") and agent not in a["agents"]:
            continue
        if "maxDataClassRank" in a and dc_rank > a["maxDataClassRank"]:
            continue
        out.append(t["id"])
    return out


def allowed_collections(policy: Policy, roles: list[str]) -> list[str]:
    return [c["id"] for c in policy.spec["rag"]["collections"] if set(c["allow"]["roles"]) & set(roles)]


def web_search_allowed(policy: Policy, roles: list[str], dc_rank: int) -> bool:
    ws = policy.spec.get("webSearch") or {"enabled": False}
    if not ws.get("enabled"):
        return False
    a = ws.get("allow") or {}
    if a.get("roles") and not set(a["roles"]) & set(roles):
        return False
    if "maxDataClassRank" in a and dc_rank > a["maxDataClassRank"]:
        return False
    return True
