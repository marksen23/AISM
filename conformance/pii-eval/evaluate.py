#!/usr/bin/env python3
"""Measures PII detection of the AISM gateway detectors.

Uses the gateway's own detector and overlap resolution (aism_gateway.pii.Masker.resolve) with the
piiDetectors of a policy (default: conformance test policy). Profiles swap the person-name setup
without editing the policy file:

  before      person-title regex + spacy:xx_ent_wiki_sm, no gazetteer (the previous default)
  spacy-md    person-title + spacy:de_core_news_md, no gazetteer
  spacy-lg    person-title + spacy:de_core_news_lg, no gazetteer
  pairs       person-title + gazetteer pairs only
  context     person-title + gazetteer context preset "de", no pairs
  gazetteer   person-title + pairs + context, no NER
  gaz-xx      gazetteer + spacy:xx_ent_wiki_sm
  gaz-md      gazetteer + spacy:de_core_news_md
  gaz-lg      gazetteer + spacy:de_core_news_lg
  gliner      person-title + gliner:urchade/gliner_multi_pii-v1 (label "person", minScore 0.35)
  gaz-gliner  gazetteer + that GLiNER model
  cascade     gazetteer + spacy:xx_ent_wiki_sm, and ner.cascade = that GLiNER model
              (minScore 0.55, default triggers; secondary runs only on suspicious sentences)
  policy      detectors exactly as in the policy file

Metrics per entity type (gold spans = annotated values; titles like "Herr Dr." are not annotated):
  recall_strict   predicted span of the same type with identical boundaries
  recall_masked   every non-space character of the gold span is covered by some predicted span
                  (any type) -> the value does not leave S2 in plaintext. Privacy-relevant.
  partial         gold spans only partly covered
  precision       predicted spans of this type that overlap a gold span of the same type
                  (false positives = over-masking, utility loss)

--gate FILE  JSON object {"PERSON": {"recall_masked": 0.90}, ...}. Exit 1 if a measured
recall_masked (rounded to 3 decimals, same as the table) is below the threshold.
Entities may carry "oov": true when not every name token is on the built-in gazetteer;
person_by_vocab then splits PERSON recall.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "gateway"))
import yaml  # noqa: E402

from aism_gateway.cascade import DEFAULT_TRIGGERS  # noqa: E402
from aism_gateway.pii import Masker, build_detectors  # noqa: E402

TYPES = ["PERSON", "EMAIL", "IBAN", "SECRET"]
GLINER_MODEL = "gliner:urchade/gliner_multi_pii-v1"
# Historical gliner / gaz-gliner profiles stay at 0.35 so earlier tables remain comparable.
# The cascade score was chosen on the dev set only (precision rose, masked recall did not fall).
GLINER_SCORE = 0.35
CASCADE_SCORE = 0.55
PROFILES = (
    "before", "spacy-md", "spacy-lg", "pairs", "context", "gazetteer",
    "gaz-xx", "gaz-md", "gaz-lg", "gliner", "gaz-gliner", "cascade", "policy",
)


def _ner(spec, model, labels, score=None):
    det = next(d for d in spec["piiDetectors"] if d["id"] == "person-name")
    det["ner"]["model"] = model
    det["ner"]["labels"] = list(labels)
    if score is not None:
        det["ner"]["minScore"] = score
    return det


def _gaz(spec):
    return next(d for d in spec["piiDetectors"] if d["id"] == "person-gazetteer")


def apply_profile(spec, profile):
    spec = copy.deepcopy(spec)
    if profile == "policy":
        return spec
    drop = set()
    if profile == "before":
        drop.add("person-gazetteer")
        _ner(spec, "spacy:xx_ent_wiki_sm", ["PER"])
    elif profile == "spacy-md":
        drop.add("person-gazetteer")
        _ner(spec, "spacy:de_core_news_md", ["PER"])
    elif profile == "spacy-lg":
        drop.add("person-gazetteer")
        _ner(spec, "spacy:de_core_news_lg", ["PER"])
    elif profile == "pairs":
        drop.add("person-name")
        g = _gaz(spec)["gazetteer"]
        g["matchPairs"] = True
        g["contextPreset"] = "none"
        g.pop("contextRules", None)
    elif profile == "context":
        drop.add("person-name")
        g = _gaz(spec)["gazetteer"]
        g["matchPairs"] = False
        g["contextPreset"] = "de"
        g.pop("contextRules", None)
    elif profile == "gazetteer":
        drop.add("person-name")
    elif profile == "gaz-xx":
        _ner(spec, "spacy:xx_ent_wiki_sm", ["PER"])
    elif profile == "gaz-md":
        _ner(spec, "spacy:de_core_news_md", ["PER"])
    elif profile == "gaz-lg":
        _ner(spec, "spacy:de_core_news_lg", ["PER"])
    elif profile == "gliner":
        drop.add("person-gazetteer")
        _ner(spec, GLINER_MODEL, ["person"], GLINER_SCORE)
    elif profile == "gaz-gliner":
        _ner(spec, GLINER_MODEL, ["person"], GLINER_SCORE)
    elif profile == "cascade":
        det = _ner(spec, "spacy:xx_ent_wiki_sm", ["PER"])
        det["ner"]["cascade"] = {
            "model": GLINER_MODEL,
            "labels": ["person"],
            "minScore": CASCADE_SCORE,
            "triggers": dict(DEFAULT_TRIGGERS),
        }
    else:
        raise SystemExit(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}")
    spec["piiDetectors"] = [d for d in spec["piiDetectors"] if d["id"] not in drop]
    return spec


def _ratio(num, den):
    return round(num / den, 3) if den else None


def _p95(samples: list[float]) -> float:
    """Nearest-rank percentile. One sample returns that sample."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[rank]


def run(rows, spec, profile, policy_dir, drop=()):
    spec = apply_profile(spec, profile)
    spec["piiDetectors"] = [d for d in spec["piiDetectors"] if d["id"] not in drop]
    detectors, errs = build_detectors(spec, base_dir=policy_dir)
    if errs:
        raise SystemExit(f"detector errors: {errs}")
    masker = Masker(detectors, {"PERSON": 2, "EMAIL": 2, "IBAN": 2, "SECRET": 3})
    st = {t: {"gold": 0, "strict": 0, "masked": 0, "partial": 0, "pred": 0, "pred_ok": 0} for t in TYPES}
    vocab = {k: {"gold": 0, "masked": 0, "strict": 0} for k in ("inv", "oov")}
    misses, fps, times = [], [], []
    for r in rows:
        t0 = time.perf_counter()
        pred = [(s, e, d.entity) for s, e, d in masker.resolve(r["text"], "prompt")]
        times.append((time.perf_counter() - t0) * 1000)
        covered = set()
        for s, e, _ in pred:
            covered.update(range(s, e))
        for g in r["entities"]:
            x = st[g["type"]]
            x["gold"] += 1
            strict = any(s == g["start"] and e == g["end"] and t == g["type"] for s, e, t in pred)
            if strict:
                x["strict"] += 1
            chars = [i for i in range(g["start"], g["end"]) if not r["text"][i].isspace()]
            n = sum(1 for i in chars if i in covered)
            masked = n == len(chars) and bool(chars)
            if masked:
                x["masked"] += 1
            else:
                if n:
                    x["partial"] += 1
                misses.append({"id": r["id"], "type": g["type"], "value": g["value"], "covered": f"{n}/{len(chars)}",
                               "tags": r["tags"], "oov": g.get("oov")})
            if g["type"] == "PERSON" and "oov" in g:
                bucket = vocab["oov" if g["oov"] else "inv"]
                bucket["gold"] += 1
                bucket["masked"] += int(masked)
                bucket["strict"] += int(strict)
        for s, e, t in pred:
            if t not in st:
                continue
            st[t]["pred"] += 1
            if any(g["type"] == t and s < g["end"] and e > g["start"] for g in r["entities"]):
                st[t]["pred_ok"] += 1
            else:
                fps.append({"id": r["id"], "type": t, "text": r["text"][s:e], "tags": r["tags"]})
    ms = sum(times) / max(len(rows), 1)
    res = {}
    for t, x in st.items():
        res[t] = {**x, "recall_strict": _ratio(x["strict"], x["gold"]),
                  "recall_masked": _ratio(x["masked"], x["gold"]),
                  "precision": _ratio(x["pred_ok"], x["pred"])}
    by_vocab = {}
    for key, bucket in vocab.items():
        if bucket["gold"]:
            by_vocab[key] = {**bucket, "recall_masked": _ratio(bucket["masked"], bucket["gold"]),
                             "recall_strict": _ratio(bucket["strict"], bucket["gold"])}
    cascade = None
    for det in detectors:
        stats = getattr(getattr(det, "cascade", None), "stats", None)
        if stats is not None:
            cascade = stats()
    return {"profile": profile, "dropped_detectors": list(drop), "ms_per_sentence": round(ms, 2),
            "ms_p95": round(_p95(times), 2),
            "per_type": res, "person_by_vocab": by_vocab, "cascade": cascade,
            "misses": misses, "false_positives": fps}


def _check_gate(runs, gate):
    failures = []
    for r in runs:
        for typ, limits in gate.items():
            got = r["per_type"].get(typ, {}).get("recall_masked")
            need = limits.get("recall_masked")
            if need is None or got is None:
                continue
            if got + 1e-9 < need:
                failures.append(f"{r['profile']} {typ} recall_masked {got:.3f} < {need:.3f}")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=str(ROOT / "conformance/tests/testdata/policy.conformance.yaml"))
    ap.add_argument("--data", action="append", help="JSONL file; repeat to concatenate. Default: pii_eval_de.jsonl")
    ap.add_argument("--profile", action="append", choices=PROFILES)
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--drop-detector", action="append", default=[], help="disable a policy detector (ablation)")
    ap.add_argument("--gate", help="JSON recall_masked thresholds; exit 1 on regression")
    ap.add_argument("--no-misses", action="store_true", help="omit miss and false-positive lists from the JSON")
    a = ap.parse_args()
    paths = a.data or [str(HERE / "pii_eval_de.jsonl")]
    rows = []
    for p in paths:
        rows.extend(json.loads(line) for line in open(p, encoding="utf-8") if line.strip())
    raw = yaml.safe_load(open(a.policy, encoding="utf-8"))
    spec = raw["spec"]
    policy_dir = str(pathlib.Path(a.policy).resolve().parent)
    profiles = a.profile or ["policy"]
    runs = [run(rows, spec, n, policy_dir, a.drop_detector) for n in profiles]
    if a.no_misses:
        for r in runs:
            r.pop("misses", None)
            r.pop("false_positives", None)
    out = {"dataset": [pathlib.Path(p).name for p in paths], "sentences": len(rows),
           "entities": {t: sum(1 for r in rows for g in r["entities"] if g["type"] == t) for t in TYPES},
           "runs": runs}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    def fmt(v):
        return "–" if v is None else f"{v:.3f}"

    for r in out["runs"]:
        drop = f", ohne {','.join(r['dropped_detectors'])}" if r["dropped_detectors"] else ""
        casc = ""
        if r.get("cascade"):
            casc = f", Kaskade {r['cascade']['trigger_fraction']} der Sätze"
        print(f"\n== {r['profile']}{drop}  (mean {r['ms_per_sentence']} ms/Satz, p95 {r['ms_p95']}{casc})")
        print(f"{'Typ':8} {'n':>4} {'R strikt':>9} {'R maskiert':>11} {'teilweise':>10} {'Präzision':>10} {'FP':>4}")
        for t, x in r["per_type"].items():
            print(f"{t:8} {x['gold']:>4} {fmt(x['recall_strict']):>9} {fmt(x['recall_masked']):>11} {x['partial']:>10} "
                  f"{fmt(x['precision']):>10} {x['pred'] - x['pred_ok']:>4}")
        if r.get("person_by_vocab"):
            for key, bucket in r["person_by_vocab"].items():
                print(f"  PERSON {key:3} n={bucket['gold']}  R maskiert={bucket['recall_masked']:.3f}")
    if a.gate:
        gate = json.loads(pathlib.Path(a.gate).read_text(encoding="utf-8"))
        failures = _check_gate(runs, gate)
        if failures:
            print("\nGATE FAILED")
            for line in failures:
                print(" ", line)
            raise SystemExit(1)
        print("\nGATE OK")


if __name__ == "__main__":
    main()
