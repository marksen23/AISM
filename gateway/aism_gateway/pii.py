"""PII detection and reversible masking (AISM PEP-2, PEP-8, PEP-10).

Detector types (Policy-Format §4.4):
  regex     – Python regular expressions
  checksum  – regex candidates verified by a checksum (iban-mod97, luhn)
  ner       – named-entity recognition; the prototype supports spaCy models
              referenced as "spacy:<model>" (e.g. spacy:xx_ent_wiki_sm)
Detection quality was measured on a small synthetic German set: conformance/pii-eval/README.md.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z_]*)_(\d+)>")
_PARTIAL_RE = re.compile(r"<[A-Z_]*\d*$")
MAX_PLACEHOLDER_LEN = 48


class DetectorUnavailable(Exception):
    pass


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in r)) % 97 == 1
    except ValueError:
        return False


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


@dataclass
class Detector:
    id: str
    entity: str
    type: str
    masking: dict
    apply_to: set[str]
    patterns: list[re.Pattern] = field(default_factory=list)
    checksum: str | None = None
    ner_labels: set[str] = field(default_factory=set)
    ner_min_score: float = 0.0
    nlp: object | None = None

    def spans(self, text: str) -> list[tuple[int, int]]:
        out = []
        if self.type in ("regex", "checksum"):
            for p in self.patterns:
                for m in p.finditer(text):
                    # a named group "pii" restricts the masked span (e.g. title + name -> only the name)
                    s, e = m.span("pii") if "pii" in p.groupindex and m.group("pii") is not None else m.span()
                    if self.type == "checksum":
                        e = self._checksum_end(text, s, e)
                        if e is None:
                            continue
                    out.append((s, e))
        elif self.type == "ner":
            # spaCy small models expose no per-entity score; minScore is not applied (documented limitation)
            for ent in self.nlp(text).ents:
                if ent.label_ in self.ner_labels:
                    out.append((ent.start_char, ent.end_char))
        return out


    def _checksum_end(self, text: str, s: int, e: int) -> int | None:
        """End of the longest checksum-valid prefix of text[s:e] that ends at a token boundary.
        Greedy patterns can swallow following uppercase tokens ("DE89 ... 00 BIC COBADEFFXXX")."""
        ok = (lambda v: _iban_ok(v)) if self.checksum == "iban-mod97" else _luhn_ok
        for end in range(e, s, -1):
            if not text[end - 1].isalnum() or (end < len(text) and text[end].isalnum()):
                continue
            if ok(text[s:end]):
                return end
            if self.checksum == "iban-mod97" and len(text[s:end].replace(" ", "")) < 15:
                break
        return None


_NLP_CACHE: dict[str, object] = {}
_NLP_LOCK = threading.Lock()


def _load_ner(model_ref: str):
    if not model_ref.startswith("spacy:"):
        raise DetectorUnavailable(f"NER-Backend nicht unterstützt: {model_ref!r} (erwartet 'spacy:<modell>')")
    name = model_ref.split(":", 1)[1]
    with _NLP_LOCK:
        if name not in _NLP_CACHE:
            try:
                import spacy  # noqa: PLC0415
                _NLP_CACHE[name] = spacy.load(name, disable=["parser", "lemmatizer", "tagger", "attribute_ruler"])
            except Exception as exc:  # model missing, import error
                raise DetectorUnavailable(f"NER-Modell {name!r} nicht ladbar: {exc}") from exc
        return _NLP_CACHE[name]


def build_detectors(policy_spec: dict) -> tuple[list[Detector], list[str]]:
    """Returns (detectors, errors). Errors mean fail-closed (M-12)."""
    dets, errors = [], []
    for d in policy_spec["piiDetectors"]:
        det = Detector(id=d["id"], entity=d["entity"], type=d["type"], masking=d["masking"],
                       apply_to=set(d.get("applyTo", ["prompt", "tool_result", "rag_ingest", "web_query"])))
        if d["type"] in ("regex", "checksum"):
            det.patterns = [re.compile(p) for p in d["patterns"]]
            det.checksum = d.get("checksum")
        else:
            det.ner_labels = set(d["ner"]["labels"])
            det.ner_min_score = d["ner"]["minScore"]
            try:
                det.nlp = _load_ner(d["ner"]["model"])
            except DetectorUnavailable as exc:
                errors.append(f"{d['id']}: {exc}")
                continue
        dets.append(det)
    return dets, errors


class Vault:
    """Request-bound placeholder table (in memory only, Spez. §6.2)."""

    def __init__(self):
        self.by_value: dict[tuple[str, str], str] = {}
        self.by_placeholder: dict[str, tuple[str, Detector]] = {}
        self.counters: dict[str, int] = {}
        self.counts: dict[str, int] = {}

    def placeholder(self, value: str, det: Detector) -> str:
        key = (det.entity, value)
        if key in self.by_value:
            return self.by_value[key]
        strat = det.masking["strategy"]
        if strat == "redact":
            ph = f"<{det.entity}_REDACTED>"
        elif strat == "hash":
            import hashlib  # noqa: PLC0415
            ph = f"<{det.entity}_{hashlib.sha256(value.encode()).hexdigest()[:10]}>"
        else:
            n = self.counters.get(det.entity, 0) + 1
            self.counters[det.entity] = n
            ph = det.masking["placeholderFormat"].replace("{n}", str(n))
            self.by_placeholder[ph] = (value, det)
        self.by_value[key] = ph
        return ph


class Masker:
    def __init__(self, detectors: list[Detector], entity_rank: dict[str, int]):
        self.detectors = detectors
        self.entity_rank = entity_rank

    def resolve(self, text: str, context: str) -> list[tuple[int, int, Detector]]:
        """Detected spans after overlap resolution (also used by conformance/pii-eval)."""
        cands = []
        for det in self.detectors:
            if context not in det.apply_to:
                continue
            for s, e in det.spans(text):
                if PLACEHOLDER_RE.fullmatch(text[s:e]):
                    continue
                cands.append((s, e, det))
        # overlap resolution: longest span wins, ties -> higher-ranked entity (Policy-Format §4.4)
        cands.sort(key=lambda c: (-(c[1] - c[0]), -self.entity_rank.get(c[2].entity, 0), c[0]))
        chosen: list[tuple[int, int, Detector]] = []
        for s, e, det in cands:
            if all(e <= cs or s >= ce for cs, ce, _ in chosen):
                chosen.append((s, e, det))
        chosen.sort(key=lambda c: c[0])
        return chosen

    def mask(self, text: str, vault: Vault, context: str) -> tuple[str, set[str]]:
        if not text:
            return text, set()
        out, pos, found = [], 0, set()
        for s, e, det in self.resolve(text, context):
            out.append(text[pos:s])
            out.append(vault.placeholder(text[s:e], det))
            vault.counts[det.entity] = vault.counts.get(det.entity, 0) + 1
            found.add(det.entity)
            pos = e
        out.append(text[pos:])
        return "".join(out), found


def demask(text: str, vault: Vault, roles: list[str]) -> str:
    def repl(m):
        hit = vault.by_placeholder.get(m.group(0))
        if not hit:
            return m.group(0)
        value, det = hit
        if det.masking.get("reversible") and set(det.masking.get("demaskFor", [])) & set(roles):
            return value
        return m.group(0)
    return PLACEHOLDER_RE.sub(repl, text)


class StreamDemasker:
    """Demasks a token stream; holds back text that may be the start of a split placeholder."""

    def __init__(self, vault: Vault, roles: list[str]):
        self.vault, self.roles, self.buf = vault, roles, ""

    def feed(self, chunk: str) -> str:
        self.buf += chunk
        idx = self.buf.rfind("<")
        if idx != -1 and _PARTIAL_RE.fullmatch(self.buf[idx:]) and len(self.buf) - idx < MAX_PLACEHOLDER_LEN:
            ready, self.buf = self.buf[:idx], self.buf[idx:]
        else:
            ready, self.buf = self.buf, ""
        return demask(ready, self.vault, self.roles)

    def flush(self) -> str:
        ready, self.buf = self.buf, ""
        return demask(ready, self.vault, self.roles)
