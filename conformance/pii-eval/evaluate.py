#!/usr/bin/env python3
"""Measures PII detection of the AISM gateway detectors on pii_eval_de.jsonl.

Uses the gateway's own detector + overlap-resolution code (aism_gateway.pii.Masker.resolve) with the
piiDetectors of a policy (default: conformance test policy). The NER model can be swapped:
  python3 evaluate.py --ner spacy:xx_ent_wiki_sm --ner spacy:de_core_news_sm --ner none
Metrics per entity type (gold spans = annotated values; titles like "Herr Dr." are not annotated):
  recall_strict   predicted span of the same type with identical boundaries
  recall_masked   every non-space character of the gold span is covered by some predicted span (any
                  type) -> the value does not leave S2 in plaintext. This is the privacy-relevant number.
  partial         gold spans only partly covered (part of the value leaks)
  precision       predicted spans of this type that overlap a gold span of the same type / all
                  predicted spans of this type (false positives = over-masking, utility loss)
"""
from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "gateway"))
import yaml  # noqa: E402

from aism_gateway.pii import Masker, build_detectors  # noqa: E402

TYPES = ["PERSON", "EMAIL", "IBAN", "SECRET"]


def run(rows, spec, ner, drop=()):
    spec = copy.deepcopy(spec)
    dets = []
    for d in spec["piiDetectors"]:
        if d["id"] in drop:
            continue
        if d["type"] == "ner":
            if ner == "none":
                continue
            d["ner"]["model"] = ner
        dets.append(d)
    spec["piiDetectors"] = dets
    detectors, errs = build_detectors(spec)
    if errs:
        raise SystemExit(f"detector errors: {errs}")
    masker = Masker(detectors, {"PERSON": 2, "EMAIL": 2, "IBAN": 2, "SECRET": 3})
    st = {t: {"gold": 0, "strict": 0, "masked": 0, "partial": 0, "pred": 0, "pred_ok": 0} for t in TYPES}
    misses, fps = [], []
    t0 = time.perf_counter()
    for r in rows:
        pred = [(s, e, d.entity) for s, e, d in masker.resolve(r["text"], "prompt")]
        covered = set()
        for s, e, _ in pred:
            covered.update(range(s, e))
        for g in r["entities"]:
            x = st[g["type"]]
            x["gold"] += 1
            if any(s == g["start"] and e == g["end"] and t == g["type"] for s, e, t in pred):
                x["strict"] += 1
            chars = [i for i in range(g["start"], g["end"]) if not r["text"][i].isspace()]
            n = sum(1 for i in chars if i in covered)
            if n == len(chars):
                x["masked"] += 1
            else:
                if n:
                    x["partial"] += 1
                misses.append({"id": r["id"], "type": g["type"], "value": g["value"], "covered": f"{n}/{len(chars)}",
                               "tags": r["tags"]})
        for s, e, t in pred:
            if t not in st:
                continue
            st[t]["pred"] += 1
            if any(g["type"] == t and s < g["end"] and e > g["start"] for g in r["entities"]):
                st[t]["pred_ok"] += 1
            else:
                fps.append({"id": r["id"], "type": t, "text": r["text"][s:e], "tags": r["tags"]})
    ms = (time.perf_counter() - t0) * 1000 / len(rows)
    res = {}
    for t, x in st.items():
        res[t] = {**x,
                  "recall_strict": round(x["strict"] / x["gold"], 3) if x["gold"] else None,
                  "recall_masked": round(x["masked"] / x["gold"], 3) if x["gold"] else None,
                  "precision": round(x["pred_ok"] / x["pred"], 3) if x["pred"] else None}
    return {"ner": ner, "dropped_detectors": list(drop), "ms_per_sentence": round(ms, 2), "per_type": res, "misses": misses, "false_positives": fps}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=str(ROOT / "conformance/tests/testdata/policy.conformance.yaml"))
    ap.add_argument("--data", default=str(HERE / "pii_eval_de.jsonl"))
    ap.add_argument("--ner", action="append")
    ap.add_argument("--out", default=str(HERE / "results.json"))
    ap.add_argument("--drop-detector", action="append", default=[], help="disable a policy detector (ablation)")
    a = ap.parse_args()
    rows = [json.loads(line) for line in open(a.data, encoding="utf-8")]
    spec = yaml.safe_load(open(a.policy, encoding="utf-8"))["spec"]
    out = {"dataset": pathlib.Path(a.data).name, "sentences": len(rows),
           "entities": {t: sum(1 for r in rows for g in r["entities"] if g["type"] == t) for t in TYPES},
           "runs": [run(rows, spec, n, a.drop_detector) for n in (a.ner or ["none", "spacy:xx_ent_wiki_sm"])]}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    for r in out["runs"]:
        drop = f", ohne {','.join(r['dropped_detectors'])}" if r["dropped_detectors"] else ""
        print(f"\n== NER: {r['ner']}{drop}  ({r['ms_per_sentence']} ms/Satz)")
        print(f"{'Typ':8} {'n':>4} {'R strikt':>9} {'R maskiert':>11} {'teilweise':>10} {'Präzision':>10} {'FP':>4}")
        for t, x in r["per_type"].items():
            f = lambda v: "–" if v is None else f"{v:.3f}"
            print(f"{t:8} {x['gold']:>4} {f(x['recall_strict']):>9} {f(x['recall_masked']):>11} {x['partial']:>10} "
                  f"{f(x['precision']):>10} {x['pred'] - x['pred_ok']:>4}")


if __name__ == "__main__":
    main()
