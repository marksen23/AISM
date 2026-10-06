#!/usr/bin/env python3
"""Rebuild the built-in German name gazetteer from open-licensed sources.

Writes gateway/aism_gateway/data/de_given_names.txt and de_surnames.txt.
Sources and licences are recorded in gateway/aism_gateway/data/README.md.
Run from the repository root: python3 tools/build_name_gazetteer.py
Needs network access. The committed lists are the ones the gateway loads;
this script is how they were produced (2026-10-06).
"""
from __future__ import annotations

import csv
import io
import json
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "gateway" / "aism_gateway" / "data"
NAME_RE = re.compile(r"^[^\W\d_]+(?:-[^\W\d_]+)*$", re.UNICODE)
# Function words only. Real given names and surnames that collide with ordinary
# vocabulary (Frank, Wolf, Lange, …) stay in the lists; pair/context matching
# limits how they fire.
STOP = {
    "und", "oder", "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "einem", "einen",
    "ist", "hat", "war", "sind", "bitte", "danke", "dankeschön", "hallo", "hi", "liebe", "lieber",
    "sehr", "frau", "herr", "herrn", "vom", "zum", "zur", "im", "am", "auf", "für", "fuer", "mit",
    "von", "van", "als", "auch", "noch", "nicht", "nur", "aber", "denn", "weil", "dass", "wenn",
    "dann", "zusammen", "kollegen", "kolleginnen", "team", "service", "abteilung", "name",
    "the", "and", "of", "to", "for",
}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "aism-gazetteer-build"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def keep(name: str, min_len: int) -> bool:
    name = name.strip()
    if len(name) < min_len or name.casefold() in STOP:
        return False
    return bool(NAME_RE.fullmatch(name))


def main() -> None:
    given: set[str] = set()
    surnames: set[str] = set()

    # CC BY 3.0 DE — Stadt Köln via https://github.com/fxnn/vornamen (frequency >= 2)
    koeln = fetch("https://raw.githubusercontent.com/fxnn/vornamen/master/vornamen-grouped-sorted.dat").decode("utf-8")
    for line in koeln.splitlines():
        name, _, count = line.strip().rpartition(" ")
        if name and count.isdigit() and int(count) >= 2 and keep(name, 3):
            given.add(name)

    # MIT — https://github.com/ndsvw/JSON-Namen
    base = "https://raw.githubusercontent.com/ndsvw/JSON-Namen/master/"
    for fn in ("vornamen_m.json", "vornamen_w.json"):
        for name in json.loads(fetch(base + fn).decode("utf-8")):
            if keep(name, 3):
                given.add(name)
    for name in json.loads(fetch(base + "nachnamen.json").decode("utf-8")):
        if keep(name, 3):
            surnames.add(name)

    # MIT — Germanic-origin given names and the most common surnames
    # https://github.com/PenTestical/german_names (ISO-8859-1)
    pent_first = fetch("https://raw.githubusercontent.com/PenTestical/german_names/master/2000_german_firstnames.txt")
    for name in pent_first.decode("latin-1").splitlines():
        if keep(name.strip(), 4):
            given.add(name.strip())
    pent_sur = fetch("https://raw.githubusercontent.com/PenTestical/german_names/master/most_common_german_surnames.txt")
    for name in pent_sur.decode("latin-1").splitlines():
        if keep(name.strip(), 3):
            surnames.add(name.strip())

    # CC0 — https://github.com/sigpwned/popular-names-by-country-dataset (DE rows only)
    fore = fetch("https://raw.githubusercontent.com/sigpwned/popular-names-by-country-dataset/main/common-forenames-by-country.csv")
    for row in csv.DictReader(io.StringIO(fore.decode("utf-8-sig"))):
        if row.get("Country") == "DE":
            name = (row.get("Localized Name") or row.get("Romanized Name") or "").strip()
            if keep(name, 3):
                given.add(name)
    sur = fetch("https://raw.githubusercontent.com/sigpwned/popular-names-by-country-dataset/main/common-surnames-by-country.csv")
    for row in csv.DictReader(io.StringIO(sur.decode("utf-8-sig"))):
        if row.get("Country") == "DE":
            name = (row.get("Localized Name") or row.get("Romanized Name") or "").strip()
            if keep(name, 3):
                surnames.add(name)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "de_given_names.txt").write_text("\n".join(sorted(given, key=str.casefold)) + "\n", encoding="utf-8")
    (OUT / "de_surnames.txt").write_text("\n".join(sorted(surnames, key=str.casefold)) + "\n", encoding="utf-8")
    print(f"given {len(given)} -> {OUT / 'de_given_names.txt'}")
    print(f"surnames {len(surnames)} -> {OUT / 'de_surnames.txt'}")


if __name__ == "__main__":
    main()
