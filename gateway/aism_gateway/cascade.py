"""Secondary NER cascade. The fast model always runs; a heavier model runs only on suspicious sentences.

Triggers (policy ``ner.cascade.triggers``; omitted keys use the defaults below):

* ``capitalizedUnknown`` – a title-case name-shaped token that is **not** the first token of its
  sentence and is not in the German common-word lexicon.
* ``sentenceStartUnknown`` – the same, but for the first token of a sentence. Ordinary sentence
  starts ("Der", "Bitte") are in the lexicon and do not fire. An out-of-lexicon token does,
  because that is the case a blanket "skip sentence start" rule would miss.
* ``unknownBigram`` – two adjacent title-case name-shaped tokens (optional nobility particle
  between them, whitespace including one newline) of which at least one is outside the lexicon.
* ``unknownLowerBigram`` – two adjacent name-shaped tokens that are not both title-case, of which
  at least one is outside the lexicon (lowercase "ines holtkamp", "anna bierstedt").
* ``listedGivenName`` – a name-shaped token on the built-in given-name list. Title case always
  counts, so "Björn" still fires when subtitle frequency also put the name in the common-word
  lexicon. A lowercase hit counts only when the token is not in that lexicon, so the verb
  "bin" (also on the given-name list) does not. Surnames are not used here. Off by default:
  on the dev set it added about 0.013 masked recall and raised the trigger rate from 0.366
  to 0.582, and it does not catch out-of-vocabulary names.
* ``nearPersonCue`` – a name-shaped token outside the lexicon within ``cueWindowTokens`` of a
  person cue (Herr/Frau/Dr., signature and greeting, Ansprechpartner, "i. V.", "Ich bin", …).
* ``lowConfidence`` – a primary-model hit whose score is below ``lowConfidenceBelow``. spaCy
  exposes no score; the marginal from a narrow beam parse is used. If that marginal cannot be
  computed, this trigger stays quiet. It does not turn the cascade off.

The lexicon is a common-word list, not the name gazetteer. Names that are also frequent German
words ("Wolf", "König") do not by themselves look unknown.

Fail-closed: if a cascade is configured, the secondary model is loaded at startup. A load failure
is a detector error and the gateway rejects requests. A runtime failure raises
``CascadeUnavailable`` (mapped to ``DetectorUnavailable``) instead of returning the fast-path
spans alone.
"""
from __future__ import annotations

import logging
import pathlib
import re
import threading
import unicodedata
from collections import defaultdict

from .person_gazetteer import _PARTICLES, _STOP, _TOKEN_RE

log = logging.getLogger("aism.gateway")

_DATA = pathlib.Path(__file__).resolve().parent / "data" / "de_common_words.txt"
_LEXICON_CACHE: frozenset[str] | None = None
_BEAM_WARNED = False

# Defaults were chosen on the dev set only (conformance/pii-eval/pii_eval_de.jsonl).
# Held-out v1, v2 and v3 were not used to change them. listedGivenName stays off: the
# recall gain on dev did not pay for the extra secondary-model calls.
DEFAULT_TRIGGERS: dict[str, bool | float | int] = {
    "capitalizedUnknown": True,
    "sentenceStartUnknown": True,
    "unknownBigram": True,
    "unknownLowerBigram": True,
    "listedGivenName": False,
    "nearPersonCue": True,
    "lowConfidence": True,
    "lowConfidenceBelow": 0.5,
    "cueWindowTokens": 4,
    "minTokenLength": 3,
    "maxSentenceChars": 2000,
}
_BOOL_KEYS = (
    "capitalizedUnknown", "sentenceStartUnknown", "unknownBigram",
    "unknownLowerBigram", "listedGivenName", "nearPersonCue", "lowConfidence",
)
_INT_KEYS = {"cueWindowTokens": (1, 12), "minTokenLength": (2, 12), "maxSentenceChars": (80, 8000)}

_ABBREV = frozenset({
    "dr", "prof", "hr", "fr", "bzw", "ca", "ggf", "inkl", "exkl", "nr", "str", "tel", "fax",
    "evtl", "usw", "etc", "dipl", "ing", "med", "phil", "rer", "nat", "jur", "univ",
})
_CUES = re.compile(
    r"(?i)(?:"
    r"\b(?:herrn?|frau|hr\.|fr\.|dr\.|prof\.)"
    r"|\bi\.\s*a\."
    r"|\bi\.\s*v\."
    r"|\bgez\."
    r"|\b(?:unterschrift|unterzeichnet(?:\s+von)?|absender|gezeichnet)\b"
    r"|\bansprechpartner(?:in)?\b"
    r"|\bich\s+bin\b"
    r"|\bich\s+hei(?:ß|ss)e\b"
    r"|\bmein\s+name\s+(?:ist|lautet)\b"
    r"|\b(?:viele|beste|herzliche|liebe|freundliche)\s+gr(?:ü|ue)(?:ß|ss)e\b"
    r"|\bmit\s+freundlichen\s+gr(?:ü|ue)(?:ß|ss)en\b"
    r"|\b(?:hallo|hi|lieber|liebe)\b"
    r"|\bsehr\s+geehrte[rn]?\b"
    r")"
)


class CascadeUnavailable(Exception):
    """Secondary model configured but not usable. Callers must not fall back to the fast path."""


def load_common_lexicon() -> frozenset[str]:
    """Casefolded German common words. Missing or empty is a hard error when a cascade is configured."""
    global _LEXICON_CACHE
    if _LEXICON_CACHE is not None:
        return _LEXICON_CACHE
    if not _DATA.is_file():
        raise CascadeUnavailable(f"deutsches Wortlexikon fehlt: {_DATA}")
    words = set()
    for line in _DATA.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        w = unicodedata.normalize("NFC", line.strip()).casefold()
        if w:
            words.add(w)
    if not words:
        raise CascadeUnavailable(f"deutsches Wortlexikon leer: {_DATA}")
    _LEXICON_CACHE = frozenset(words)
    return _LEXICON_CACHE


def split_sentences(text: str) -> list[tuple[int, int]]:
    """Sentence spans. Newlines split; periods after a digit or a known abbreviation do not."""
    spans: list[tuple[int, int]] = []
    start = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\n" or (ch in ".!?" and _should_split(text, i)):
            # Newlines are boundaries, not part of the sentence. A period stays in the sentence,
            # and i must move past it — leaving i on the newline would spin forever.
            _append_span(text, spans, start, i if ch == "\n" else i + 1)
            i += 1
            while i < n and text[i] in " \t\r":
                i += 1
            start = i
            continue
        i += 1
    _append_span(text, spans, start, n)
    return spans


def _append_span(text: str, spans: list[tuple[int, int]], start: int, end: int) -> None:
    a = start
    while a < end and text[a] in " \t\r":
        a += 1
    b = end
    while b > a and text[b - 1] in " \t\r":
        b -= 1
    if a < b and text[a:b].strip():
        spans.append((a, b))


def _is_abbrev_period(text: str, i: int) -> bool:
    j = i - 1
    while j >= 0 and text[j].isalpha():
        j -= 1
    word = text[j + 1:i]
    if not word:
        return False
    return len(word) == 1 or word.casefold() in _ABBREV


def _should_split(text: str, i: int) -> bool:
    if text[i] == "." and i > 0 and (text[i - 1].isdigit() or _is_abbrev_period(text, i)):
        return False
    nxt = i + 1
    return nxt >= len(text) or text[nxt].isspace()


def _name_shaped(token: str, min_len: int) -> bool:
    if len(token) < min_len or token.casefold() in _STOP:
        return False
    parts = token.split("-")
    if any(not part or (part.isupper() and len(part) <= 4) for part in parts):
        return False
    return all(part.isalpha() for part in parts)


def _title_case(token: str) -> bool:
    return bool(token) and token[0].isupper() and not token.isupper()


def _adjacent(text: str, left: re.Match[str], right: re.Match[str]) -> bool:
    gap = text[left.end():right.start()]
    return gap.strip() == "" and gap.count("\n") <= 1 and not any(c in gap for c in ".!?")


def _sent_index(sentences: list[tuple[int, int]], pos: int) -> int | None:
    for i, (s, e) in enumerate(sentences):
        if s <= pos < e:
            return i
    return None


def spacy_confidence(doc, ner, labels: set[str]) -> dict[tuple[int, int], float]:
    """Beam-marginal P(span) for labels the primary detector keeps. Empty if the beam cannot be read."""
    global _BEAM_WARNED
    try:
        beams = ner.beam_parse([doc], beam_width=8, beam_density=0.0001)
        out: dict[tuple[int, int], float] = {}
        for beam in beams:
            parses = list(ner.moves.get_beam_parses(beam))
            total = 0.0
            acc: dict[tuple[int, int], float] = {}
            for score, ents in parses:
                weight = float(score)
                if weight <= 0:
                    continue
                total += weight
                for ts, te, lab in ents:
                    if lab not in labels or te <= ts:
                        continue
                    span = doc[ts:te]
                    key = (span.start_char, span.end_char)
                    acc[key] = acc.get(key, 0.0) + weight
            if total <= 0:
                continue
            for key, weight in acc.items():
                out[key] = max(out.get(key, 0.0), weight / total)
        return out
    except Exception as exc:  # beam internals differ across spaCy builds; the other triggers still run
        if not _BEAM_WARNED:
            _BEAM_WARNED = True
            log.warning("spaCy-Konfidenz nicht berechenbar, Trigger lowConfidence bleibt still: %s", exc)
        return {}


def suspicious_sentences(
    text: str,
    settings: dict,
    lexicon: frozenset[str],
    primary: list[tuple[int, int, float | None]] | None = None,
    confidence: dict[tuple[int, int], float] | None = None,
    given: frozenset[str] | None = None,
) -> tuple[list[tuple[int, int]], dict[int, set[str]], dict[int, list[tuple[int, int]]]]:
    """Return (sentence spans, reasons per sentence, suspicious token spans per sentence)."""
    sentences = split_sentences(text)
    reasons: dict[int, set[str]] = defaultdict(set)
    tokens_at: dict[int, list[tuple[int, int]]] = defaultdict(list)
    if not sentences:
        return sentences, reasons, tokens_at
    tokens = list(_TOKEN_RE.finditer(text))
    given = given or frozenset()
    min_len = int(settings["minTokenLength"])
    window = int(settings["cueWindowTokens"])

    def mark(sid: int | None, reason: str, span: tuple[int, int] | None) -> None:
        if sid is None:
            return
        reasons[sid].add(reason)
        if span is not None:
            tokens_at[sid].append(span)

    shaped: list[bool] = []
    folded: list[str] = []
    for tok in tokens:
        raw = tok.group()
        folded.append(raw.casefold())
        shaped.append(_name_shaped(raw, min_len))

    sent_of = [_sent_index(sentences, tok.start()) for tok in tokens]
    at_start: list[bool] = []
    for i, sid in enumerate(sent_of):
        at_start.append(i == 0 or sid is None or sid != sent_of[i - 1])

    for i, tok in enumerate(tokens):
        if not shaped[i]:
            continue
        sid = sent_of[i]
        outside = folded[i] not in lexicon
        if _title_case(tok.group()) and outside:
            if at_start[i] and settings["sentenceStartUnknown"]:
                mark(sid, "sentenceStartUnknown", tok.span())
            if not at_start[i] and settings["capitalizedUnknown"]:
                mark(sid, "capitalizedUnknown", tok.span())
        if settings["listedGivenName"] and folded[i] in given and (_title_case(tok.group()) or outside):
            # Lowercase hits that are also ordinary words ("bin") are not names. Title case still is.
            mark(sid, "listedGivenName", tok.span())
        j = i + 1
        if j < len(tokens) and folded[j] in _PARTICLES and _adjacent(text, tok, tokens[j]):
            j += 1
        if j >= len(tokens) or not shaped[j]:
            continue
        if j == i + 1 and not _adjacent(text, tok, tokens[j]):
            continue
        if j > i + 1 and not (_adjacent(text, tok, tokens[i + 1]) and _adjacent(text, tokens[j - 1], tokens[j])):
            continue
        right_tok = tokens[j]
        both_title = _title_case(tok.group()) and _title_case(right_tok.group())
        pair_span = (tok.start(), right_tok.end())
        if both_title and settings["unknownBigram"] and (folded[i] not in lexicon or folded[j] not in lexicon):
            mark(sent_of[i], "unknownBigram", pair_span)
            mark(sent_of[j], "unknownBigram", pair_span)
        elif (not both_title) and settings["unknownLowerBigram"] and (folded[i] not in lexicon or folded[j] not in lexicon):
            mark(sent_of[i], "unknownLowerBigram", pair_span)
            mark(sent_of[j], "unknownLowerBigram", pair_span)

    if settings["nearPersonCue"] and tokens:
        for cue in _CUES.finditer(text):
            idxs = [i for i, tok in enumerate(tokens) if tok.start() < cue.end() and tok.end() > cue.start()]
            if not idxs:
                continue
            lo, hi = min(idxs), max(idxs)
            for i in range(max(0, lo - window), min(len(tokens), hi + 1 + window)):
                if lo <= i <= hi or not shaped[i] or folded[i] in lexicon:
                    continue
                mark(sent_of[i], "nearPersonCue", tokens[i].span())

    if settings["lowConfidence"]:
        conf = confidence or {}
        below = float(settings["lowConfidenceBelow"])
        for start, end, score in primary or []:
            sid = _sent_index(sentences, start)
            got = score if score is not None else conf.get((start, end))
            if got is not None and got < below:
                mark(sid, "lowConfidence", (start, end))
    return sentences, reasons, tokens_at


class Cascade:
    def __init__(self, model_ref: str, labels: set[str], min_score: float, runner, lexicon: frozenset[str], settings: dict):
        self.model_ref = model_ref
        self.labels = labels
        self.min_score = min_score
        self.runner = runner
        self.lexicon = lexicon
        self.given = frozenset()
        self.settings = settings
        self.sentences = 0
        self.triggered = 0
        self.reason_counts = {k: 0 for k in _BOOL_KEYS}
        self._lock = threading.Lock()

    @classmethod
    def from_policy(cls, cfg: dict, runner, lexicon: frozenset[str]) -> Cascade:
        triggers = cfg.get("triggers") or {}
        if not isinstance(triggers, dict):
            raise CascadeUnavailable("ner.cascade.triggers muss ein Objekt sein")
        unknown = sorted(set(triggers) - set(DEFAULT_TRIGGERS))
        if unknown:
            raise CascadeUnavailable(f"unbekannte Kaskaden-Trigger: {', '.join(unknown)}")
        settings = dict(DEFAULT_TRIGGERS)
        for key in _BOOL_KEYS:
            if key not in triggers:
                continue
            if not isinstance(triggers[key], bool):
                raise CascadeUnavailable(f"Kaskaden-Trigger {key} muss bool sein")
            settings[key] = triggers[key]
        if "lowConfidenceBelow" in triggers:
            raw = triggers["lowConfidenceBelow"]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise CascadeUnavailable("lowConfidenceBelow muss eine Zahl sein")
            val = float(raw)
            if not 0 <= val <= 1:
                raise CascadeUnavailable("lowConfidenceBelow muss zwischen 0 und 1 liegen")
            settings["lowConfidenceBelow"] = val
        for key, (lo, hi) in _INT_KEYS.items():
            if key not in triggers:
                continue
            raw = triggers[key]
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise CascadeUnavailable(f"{key} muss eine ganze Zahl sein")
            if not lo <= raw <= hi:
                raise CascadeUnavailable(f"{key} muss zwischen {lo} und {hi} liegen")
            settings[key] = raw
        labels = cfg.get("labels") or []
        if not labels:
            raise CascadeUnavailable("ner.cascade.labels fehlt")
        model = str(cfg.get("model") or "")
        if ":" not in model:
            raise CascadeUnavailable(f"Kaskaden-Modell {model!r} muss 'spacy:<modell>' oder 'gliner:<modell>' sein")
        try:
            min_score = float(cfg["minScore"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CascadeUnavailable("ner.cascade.minScore fehlt oder ist keine Zahl") from exc
        from .person_gazetteer import load_name_list  # noqa: PLC0415
        try:
            given = load_name_list("builtin:de-given", None)
        except Exception as exc:
            raise CascadeUnavailable(f"Vornamensliste für den Kaskaden-Trigger nicht ladbar: {exc}") from exc
        obj = cls(model, set(labels), min_score, runner, lexicon, settings)
        obj.given = given
        return obj

    def stats(self) -> dict:
        with self._lock:
            sentences, triggered = self.sentences, self.triggered
            reasons = dict(self.reason_counts)
        return {
            "sentences": sentences,
            "triggered": triggered,
            "trigger_fraction": round(triggered / sentences, 3) if sentences else None,
            "reasons": reasons,
            "triggers": dict(self.settings),
        }

    def extra_spans(
        self,
        text: str,
        primary: list[tuple[int, int, float | None]],
        confidence_fn=None,
    ) -> list[tuple[int, int]]:
        sentences, reasons, token_spans = suspicious_sentences(
            text, self.settings, self.lexicon, primary, None, self.given)
        if self.settings["lowConfidence"] and confidence_fn is not None and any(
            score is None and _sent_index(sentences, start) not in reasons
            for start, _, score in primary
        ):
            # Beam only for a primary hit that has no score and sits in a sentence the lexicon did not select.
            sentences, reasons, token_spans = suspicious_sentences(
                text, self.settings, self.lexicon, primary, confidence_fn(), self.given)
        with self._lock:
            self.sentences += len(sentences)
            self.triggered += len(reasons)
            for why in reasons.values():
                for key in why:
                    self.reason_counts[key] = self.reason_counts.get(key, 0) + 1
        if not reasons:
            return []
        limit = int(self.settings["maxSentenceChars"])
        found: list[tuple[int, int]] = []
        for sid in sorted(reasons):
            sent_s, sent_e = sentences[sid]
            for w0, w1 in _windows(sent_s, sent_e, token_spans.get(sid) or [], limit):
                found.extend(self._run(text[w0:w1], w0))
        return found

    def _run(self, chunk: str, offset: int) -> list[tuple[int, int]]:
        if not chunk.strip():
            return []
        try:
            doc = self.runner(chunk)
        except CascadeUnavailable:
            raise
        except Exception as exc:
            raise CascadeUnavailable(
                f"Kaskaden-Modell {self.model_ref!r} ist ausgefallen und wird nicht still übersprungen: {exc}"
            ) from exc
        out = []
        for ent in getattr(doc, "ents", ()):
            if ent.label_ not in self.labels:
                continue
            score = getattr(ent, "score", None)
            if score is not None and float(score) < self.min_score:
                continue
            s, e = int(ent.start_char), int(ent.end_char)
            if 0 <= s < e <= len(chunk):
                out.append((s + offset, e + offset))
        return out


def _windows(sent_s: int, sent_e: int, spans: list[tuple[int, int]], limit: int) -> list[tuple[int, int]]:
    if sent_e - sent_s <= limit:
        return [(sent_s, sent_e)]
    if not spans:
        return [(sent_s, min(sent_e, sent_s + limit))]
    raw = []
    for a, b in spans:
        mid = (max(a, sent_s) + min(b, sent_e)) // 2
        w0 = max(sent_s, mid - limit // 2)
        w1 = min(sent_e, w0 + limit)
        w0 = max(sent_s, w1 - limit)
        raw.append((w0, w1))
    raw.sort()
    merged = [raw[0]]
    for a, b in raw[1:]:
        if a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    out = []
    for a, b in merged:
        x = a
        while x < b:
            out.append((x, min(b, x + limit)))
            x += limit
    return out
