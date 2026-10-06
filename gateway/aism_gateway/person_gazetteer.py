"""German person-name gazetteer and context rules (policy detector type ``gazetteer``).

Two signals, both configurable from the policy:

* **Pairs.** Two adjacent tokens (whitespace only) whose case-folded forms are a listed
  given name and a listed surname. This catches "Anna Müller" and "ines wagner" without
  requiring capitals. An optional nobility particle (von, van, de, …) may sit between them.
* **Context rules.** A cue ("mein Name ist", a salutation, a signature, "Danke …") plus a
  short candidate. ``accept: cue`` keeps a single token only when it is on a list, and keeps
  two or three name-shaped tokens even when they are not (so "mein Name ist <unknown>" still
  masks, while "Mein Name ist im Telefonbuch" does not). ``accept: gazetteer-all`` keeps the
  candidate only when every token is listed (salutations, "Danke Max", "<Name> sagt").

Titles such as "Frau Müller" stay in the ``person-title`` regex detector; they do not need
the gazetteer, so an unknown surname after Herr/Frau/Dr. is still masked.
"""
from __future__ import annotations

import pathlib
import re

class GazetteerError(Exception):
    """Bad gazetteer configuration or unreadable list. The gateway treats this as fail-closed."""

_TOKEN_RE = re.compile(r"[^\W\d_]+(?:-[^\W\d_]+)*", re.UNICODE)
_TOKEN = r"[^\W\d_]+(?:-[^\W\d_]+)*"
_CAND = rf"(?P<pii>{_TOKEN}(?:[ \t]+{_TOKEN}){{0,2}})"
_PARTICLES = frozenset({"von", "van", "de", "da", "del", "di", "zu"})
# Trailing/leading words a cue pattern may swallow. Not removed from the gazetteer.
_STOP = frozenset({
    "und", "oder", "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "einem", "einen",
    "ist", "hat", "war", "sind", "bitte", "danke", "dankeschön", "hallo", "hi", "liebe", "lieber",
    "sehr", "frau", "herr", "herrn", "dr", "prof", "vom", "zum", "zur", "im", "am", "auf", "für",
    "fuer", "mit", "von", "van", "de", "da", "als", "auch", "noch", "nicht", "nur", "aber", "denn",
    "weil", "dass", "wenn", "dann", "so", "zu", "in", "an", "ab", "bei", "nach", "vor", "über",
    "uber", "unter", "aus", "durch", "gegen", "ohne", "um", "bis", "the", "and", "of", "to", "for",
    "zusammen", "kollegen", "kolleginnen", "team", "service", "abteilung", "buchhaltung", "personal",
    "support", "name", "mein", "meine", "ist",
})
_BUILTIN = {
    "builtin:de-given": "de_given_names.txt",
    "builtin:de-surnames": "de_surnames.txt",
}
_DATA = pathlib.Path(__file__).resolve().parent / "data"

# Reference preset ``de``. Operators replace it with gazetteer.contextRules.
_GRUSS = (
    r"(?:viele\s+gr(?:ü|ue)(?:ß|ss)e|mit\s+freundlichen\s+gr(?:ü|ue)(?:ß|ss)en|"
    r"beste\s+gr(?:ü|ue)(?:ß|ss)e|herzliche\s+gr(?:ü|ue)(?:ß|ss)e|"
    r"freundliche\s+gr(?:ü|ue)(?:ß|ss)e|liebe\s+gr(?:ü|ue)(?:ß|ss)e)"
)
DEFAULT_CONTEXT_RULES: list[dict] = [
    {
        "accept": "cue",
        "patterns": [
            rf"(?i)\b(?:mein\s+name\s+ist|ich\s+hei(?:ß|ss)e|mein\s+name\s+lautet)\s+{_CAND}",
            rf"(?i)\b(?:absender|unterschrift|unterzeichnet\s+von|i\.\s*a\.)\s*[:：]?\s*{_CAND}",
            rf"(?i){_GRUSS}\s*[,:]?\s+{_CAND}",
        ],
    },
    {
        "accept": "gazetteer-all",
        "patterns": [
            rf"(?i)\b(?:hallo|hi|lieber|liebe|sehr\s+geehrter|sehr\s+geehrte)\s+(?:(?:herrn?|frau)\s+)?{_CAND}",
            rf"(?i)\b(?:danke|dankeschön|vielen\s+dank)\s*[,!]?\s+{_CAND}",
            rf"(?i)\b{_CAND}\s+(?:sagt|meinte?|schreibt|meldet|berichtet)\b",
        ],
    },
]

_LIST_CACHE: dict[str, frozenset[str]] = {}


def load_name_list(ref: str, base_dir: str | None) -> frozenset[str]:
    """``builtin:de-given`` / ``builtin:de-surnames`` or ``file:<path>`` relative to the policy directory."""
    if ref in _LIST_CACHE and ref.startswith("builtin:"):
        return _LIST_CACHE[ref]
    if ref.startswith("builtin:"):
        fn = _BUILTIN.get(ref)
        if not fn:
            raise GazetteerError(f"unbekanntes Gazetteer {ref!r} (builtin:de-given, builtin:de-surnames)")
        path = _DATA / fn
    elif ref.startswith("file:"):
        rel = ref[5:]
        if not rel or rel.startswith(("/", "\\")) or ".." in pathlib.PurePosixPath(rel.replace("\\", "/")).parts:
            raise GazetteerError(f"Gazetteer-Pfad ungültig: {ref!r}")
        if not base_dir:
            raise GazetteerError(f"{ref!r} braucht das Verzeichnis der Policy-Datei")
        path = pathlib.Path(base_dir) / rel
    else:
        raise GazetteerError(f"Gazetteer-Referenz {ref!r} muss builtin: oder file: sein")
    if not path.is_file():
        raise GazetteerError(f"Gazetteer-Datei fehlt: {path}")
    names = frozenset(
        line.strip().casefold()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )
    if not names:
        raise GazetteerError(f"Gazetteer leer: {path}")
    if ref.startswith("builtin:"):
        _LIST_CACHE[ref] = names
    return names


def compile_context_rules(spec: dict) -> list[tuple[str, list[re.Pattern[str]]]]:
    """Policy ``contextRules`` replace the preset. Otherwise ``contextPreset`` (default ``de``)."""
    if "contextRules" in spec:
        raw = spec.get("contextRules") or []
    else:
        preset = spec.get("contextPreset", "de")
        if preset == "none":
            raw = []
        elif preset == "de":
            raw = DEFAULT_CONTEXT_RULES
        else:
            raise GazetteerError(f"contextPreset {preset!r} ist unbekannt (de, none)")
    out = []
    for rule in raw:
        accept = rule.get("accept")
        if accept not in ("cue", "gazetteer-all", "gazetteer-any"):
            raise GazetteerError(f"gazetteer.accept {accept!r} ist unbekannt")
        compiled = []
        for pat in rule.get("patterns") or []:
            try:
                cre = re.compile(pat)
            except re.error as exc:
                raise GazetteerError(f"Gazetteer-Kontextmuster ungültig: {exc}") from exc
            if "pii" not in cre.groupindex:
                raise GazetteerError("Gazetteer-Kontextmuster braucht die benannte Gruppe (?P<pii>…)")
            compiled.append(cre)
        if compiled:
            out.append((accept, compiled))
    return out


def _trim(text: str, start: int, end: int, accept: str, given: frozenset[str], surnames: frozenset[str]):
    """Return the name span inside text[start:end], or None."""
    region = text[start:end]
    toks = list(_TOKEN_RE.finditer(region))
    kept = []
    for tok in toks:
        folded = tok.group().casefold()
        if folded in _STOP or (tok.group().isupper() and len(tok.group()) <= 4 and "-" not in tok.group()):
            if kept:
                break
            continue
        # Hyphenated tokens that are not listed ("IT-Service") are not part of a name.
        if "-" in tok.group() and folded not in given and folded not in surnames:
            if kept:
                break
            continue
        kept.append(tok)
        if len(kept) == 3:
            break
    if not kept:
        return None

    def listed(tok: re.Match[str]) -> bool:
        folded = tok.group().casefold()
        return folded in given or folded in surnames

    if accept == "cue":
        if len(kept) == 1 and not listed(kept[0]):
            return None
    elif accept == "gazetteer-all":
        if not all(listed(tok) for tok in kept):
            return None
    elif accept == "gazetteer-any":
        if not any(listed(tok) for tok in kept):
            return None
    else:
        return None
    return start + kept[0].start(), start + kept[-1].end()


def person_spans(text: str, given: frozenset[str], surnames: frozenset[str], match_pairs: bool,
                 rules: list[tuple[str, list[re.Pattern[str]]]]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    if match_pairs:
        toks = list(_TOKEN_RE.finditer(text))
        for i, first in enumerate(toks):
            if first.group().casefold() not in given:
                continue
            j = i + 1
            if j >= len(toks):
                continue
            gap = text[first.end():toks[j].start()]
            if not gap.isspace():
                continue
            if toks[j].group().casefold() in _PARTICLES and j + 1 < len(toks):
                gap2 = text[toks[j].end():toks[j + 1].start()]
                if gap2.isspace() and toks[j + 1].group().casefold() in surnames:
                    spans.append((first.start(), toks[j + 1].end()))
                continue
            if toks[j].group().casefold() in surnames:
                spans.append((first.start(), toks[j].end()))
    for accept, patterns in rules:
        for cre in patterns:
            for match in cre.finditer(text):
                if match.group("pii") is None:
                    continue
                span = _trim(text, *match.span("pii"), accept, given, surnames)
                if span:
                    spans.append(span)
    return spans
