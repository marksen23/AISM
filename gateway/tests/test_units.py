"""Unit tests for the gateway prototype (run: python -m pytest gateway/tests)."""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "gateway"))

from aism_gateway import trace  # noqa: E402
from aism_gateway.audit import AuditLog, verify_chain  # noqa: E402
from aism_gateway.pii import Masker, StreamDemasker, Vault, build_detectors, demask  # noqa: E402
from aism_gateway.policy import PolicyError, load_policy  # noqa: E402

POLICY = ROOT / "policy" / "policy.example.yaml"
SCHEMA = ROOT / "policy" / "policy.schema.json"


@pytest.fixture(scope="module")
def pol():
    return load_policy(POLICY, SCHEMA)


@pytest.fixture(scope="module")
def masker(pol):
    dets, errs = build_detectors(pol.spec)
    assert not errs, errs
    return Masker(dets, {"PERSON": 2, "EMAIL": 2, "IBAN": 2, "SECRET": 3})


def test_mask_and_demask_roundtrip(masker):
    v = Vault()
    text = "Erika Mustermann (erika.mustermann@example.com) schickte AKIAIOSFODNN7EXAMPLE; nochmal erika.mustermann@example.com"
    out, ents = masker.mask(text, v, "prompt")
    assert "erika.mustermann@example.com" not in out and "AKIAIOSFODNN7EXAMPLE" not in out
    assert out.count("<EMAIL_1>") == 2, out           # same value -> same placeholder
    assert {"EMAIL", "SECRET"} <= ents
    back = demask(out, v, ["staff"])
    assert "erika.mustermann@example.com" in back
    assert "<SECRET_1>" in back                        # secrets are never demasked
    assert demask(out, v, []) == out                   # no role -> no demasking


def test_iban_checksum(masker):
    v = Vault()
    out, _ = masker.mask("IBAN DE89370400440532013000 und DE00370400440532013000", v, "prompt")
    assert "<IBAN_1>" in out and "DE00370400440532013000" in out


@pytest.mark.parametrize("split", [1, 2, 3, 5, 7])
def test_stream_demask_split_placeholders(masker, split):
    v = Vault()
    masked, _ = masker.mask("Mail an max.mustermann@example.org und erika.mustermann@example.com.", v, "prompt")
    d = StreamDemasker(v, ["staff"])
    pieces = [masked[i:i + split] for i in range(0, len(masked), split)]
    out = "".join(d.feed(p) for p in pieces) + d.flush()
    assert out == "Mail an max.mustermann@example.org und erika.mustermann@example.com."


def test_stream_demask_does_not_hold_plain_angle_brackets(masker):
    d = StreamDemasker(Vault(), ["staff"])
    assert d.feed("a < b ") == "a < b "
    assert d.feed("<EMA") == ""
    assert d.feed("IL_9> x") == "<EMAIL_9> x"        # unknown placeholder stays as is


def test_audit_chain(tmp_path, pol):
    p = tmp_path / "a.jsonl"
    a = AuditLog(str(p))
    for i in range(3):
        a.write("request.accepted", pol.info(), request_id=f"r{i}")
    AuditLog(str(p)).write("request.accepted", pol.info(), request_id="after-restart")
    assert verify_chain(str(p)) == []
    lines = p.read_text().splitlines()
    lines[1] = lines[1].replace("r1", "rX")
    p.write_text("\n".join(lines) + "\n")
    assert verify_chain(str(p)) == [3]


def test_policy_semantic_error(tmp_path):
    bad = POLICY.read_text().replace("priority: 800", "priority: 900")
    f = tmp_path / "p.yaml"
    f.write_text(bad)
    with pytest.raises(PolicyError):
        load_policy(f, SCHEMA)


_PERSON_MASK = {"strategy": "placeholder", "placeholderFormat": "<PERSON_{n}>", "reversible": True, "demaskFor": ["staff"]}
_TITLE_PATTERNS = [
    r"\b(?:Herrn?|Frau|Hr\.|Fr\.)\s+(?:(?:Dr|Prof)\.\s+)*(?P<pii>[A-ZÄÖÜÇŞİ][^\W\d_]+(?:-[A-ZÄÖÜ][^\W\d_]+)?(?:\s+[A-ZÄÖÜÇŞİ][^\W\d_]+(?:-[A-ZÄÖÜ][^\W\d_]+)?)?)",
    r"\b(?:Dr|Prof)\.\s+(?P<pii>[A-ZÄÖÜÇŞİ][^\W\d_]+(?:-[A-ZÄÖÜ][^\W\d_]+)?(?:\s+[A-ZÄÖÜÇŞİ][^\W\d_]+)?)",
]


def _gazetteer_masker():
    spec = {"piiDetectors": [
        {"id": "person-title", "entity": "PERSON", "type": "regex", "patterns": _TITLE_PATTERNS, "masking": _PERSON_MASK},
        {"id": "person-gazetteer", "entity": "PERSON", "type": "gazetteer", "masking": _PERSON_MASK,
         "gazetteer": {"givenNames": "builtin:de-given", "surnames": "builtin:de-surnames",
                       "matchPairs": True, "contextPreset": "de"}},
    ]}
    dets, errs = build_detectors(spec)
    assert not errs, errs
    return Masker(dets, {"PERSON": 2})


def _masked(masker, text):
    out, _ = masker.mask(text, Vault(), "prompt")
    return out


def test_gazetteer_pairs_and_context_rules():
    m = _gazetteer_masker()
    pair = _masked(m, "anna müller").casefold()
    assert "anna" not in pair and "müller" not in pair
    assert "ines" not in _masked(m, "mein name ist ines holtkamp").casefold()
    assert "nkechi" not in _masked(m, "Mein Name ist Nkechi Ngono").casefold()
    assert "sabine" not in _masked(m, "Unterschrift: Sabine Holtkamp").casefold()
    assert "chinedu" not in _masked(m, "i. A. Chinedu Çelik").casefold()
    assert "<PERSON_1>" in _masked(m, "Danke, Max!")
    assert "<PERSON_1>" in _masked(m, "Liebe Anna")
    assert "<PERSON_1>" in _masked(m, "Anna sagt hallo")
    signed = _masked(m, "Viele Grüße, Anna Müller\nIT-Service")
    assert "Anna" not in signed and "Müller" not in signed and "IT-Service" in signed
    titled = _masked(m, "Frau Müller hat geschrieben")
    assert "Frau" in titled and "Müller" not in titled
    for plain in (
        "Mein Name ist im Telefonbuch",
        "Hallo zusammen",
        "Max. 5 Geräte",
        "frank und frei",
        "kannst du ines holtkamp bescheid geben",
        "Wer sagt das",
        "Firma Müller GmbH",
        "Projekt Phoenix",
        "Viele Grüße\nIT-Service",
    ):
        assert _masked(m, plain) == plain, plain


def test_example_policy_masks_mustermann(masker):
    out, ents = masker.mask("Erika Mustermann und Max Mustermann", Vault(), "prompt")
    assert "Erika" not in out and "Max" not in out and "Mustermann" not in out
    assert "PERSON" in ents


def test_gazetteer_absolute_file_rejected(tmp_path):
    bad = POLICY.read_text().replace("givenNames: builtin:de-given", "givenNames: file:/etc/passwd")
    path = tmp_path / "p.yaml"
    path.write_text(bad)
    with pytest.raises(PolicyError):
        load_policy(path, SCHEMA)


def test_default_policy_has_no_cascade(pol):
    person = next(d for d in pol.spec["piiDetectors"] if d["id"] == "person-name")
    assert "cascade" not in person["ner"]


def test_cascade_triggers_and_lexicon():
    from aism_gateway.cascade import Cascade, load_common_lexicon, split_sentences, suspicious_sentences

    lex = load_common_lexicon()
    assert "server" in lex and "frankfurt" in lex
    assert "holtkamp" not in lex and "nkechi" not in lex
    assert "grüße".casefold() in lex
    casc = Cascade.from_policy(
        {"model": "gliner:test/model", "labels": ["person"], "minScore": 0.35},
        lambda text: None, lex)

    def why(text, primary=(), **overrides):
        settings = dict(casc.settings)
        settings.update(overrides)
        _sents, reasons, _spans = suspicious_sentences(text, settings, lex, list(primary), given=casc.given)
        return set().union(*reasons.values()) if reasons else set()

    assert "capitalizedUnknown" in why("Bitte Holtkamp heute anrufen.")
    assert why("Der Server in Frankfurt ist online.") == set()
    assert "nearPersonCue" in why("Ich bin nkechi und rufe an.")
    assert why("Ich bin im Büro.") == set()
    assert "unknownLowerBigram" in why("kannst du nkechi ngono bescheid geben")
    assert "unknownLowerBigram" in why("ines holtkamp bleibt zuhause")
    assert "listedGivenName" in why("Björn ist hier.", listedGivenName=True)
    assert why("Björn ist hier.") == set()
    assert "unknownBigram" in why("Ngono Holtkamp kam vorbei.")
    assert why("Holtkamp ist hier.", sentenceStartUnknown=False) == set()
    assert "sentenceStartUnknown" in why("Holtkamp ist hier.")
    server = "Der Server läuft."
    s = server.index("Server")
    assert "lowConfidence" in why(server, primary=[(s, s + 6, 0.2)])
    assert why(server, primary=[(s, s + 6, 0.9)]) == set()
    assert split_sentences("Dr. Braun kam.") == [(0, len("Dr. Braun kam."))]
    assert len(split_sentences("i. V. Holtkamp")) == 1
    assert len(split_sentences("Satz eins. Satz zwei.")) == 2
    assert len(split_sentences("Viele Grüße\nHoltkamp")) == 2
    assert len(split_sentences("Release 2.3.1 ist da.")) == 1


class _Ent:
    def __init__(self, s, e, label="person", score=0.95):
        self.start_char, self.end_char, self.label_, self.score = s, e, label, score


class _FixedNlp:
    def __init__(self, ents):
        self._ents = ents

    def __call__(self, text):
        return type("Doc", (), {"ents": self._ents})()


class _BoomNlp:
    def __call__(self, text):
        raise RuntimeError("secondary down")


def _cascade_detector(primary_ents, runner):
    from aism_gateway.cascade import Cascade, load_common_lexicon
    from aism_gateway.pii import Detector

    det = Detector(id="person-name", entity="PERSON", type="ner", masking=_PERSON_MASK, apply_to={"prompt"})
    det.ner_labels = {"PER"}
    det.ner_min_score = 0.8
    det.ner_backend = "spacy"
    det.nlp = _FixedNlp(primary_ents)
    det.cascade = Cascade.from_policy(
        {"model": "gliner:test/model", "labels": ["person"], "minScore": 0.35},
        runner, load_common_lexicon())
    return det


def test_cascade_unions_masks_and_demasks_stream():
    text = "Bitte Holtkamp heute anrufen."
    start = text.index("Holtkamp")
    det = _cascade_detector([], _FixedNlp([_Ent(start, start + len("Holtkamp"))]))
    masker = Masker([det], {"PERSON": 2})
    vault = Vault()
    out, ents = masker.mask(text, vault, "prompt")
    assert "Holtkamp" not in out and "PERSON" in ents
    assert "Bitte" in out and "anrufen" in out
    masked = out
    demasked = demask(masked, vault, ["staff"])
    assert "Holtkamp" in demasked
    stream = StreamDemasker(vault, ["staff"])
    assert "".join(stream.feed(masked[i:i + 3]) for i in range(0, len(masked), 3)) + stream.flush() == demasked
    assert det.cascade.stats()["triggered"] >= 1


def test_cascade_runtime_failure_does_not_return_fast_path_only():
    from aism_gateway.pii import DetectorUnavailable

    text = "Bitte Holtkamp heute anrufen."
    start = text.index("Holtkamp")
    det = _cascade_detector([_Ent(start, start + len("Holtkamp"), "PER", None)], _BoomNlp())
    with pytest.raises(DetectorUnavailable):
        det.spans(text)


def test_cascade_unavailable_at_load_is_fail_closed(monkeypatch):
    import aism_gateway.pii as pii

    real = pii._load_backend

    def wrapped(kind, name):
        if kind == "gliner":
            raise ImportError("gliner missing")
        return real(kind, name)

    monkeypatch.setattr(pii, "_load_backend", wrapped)
    spec = {"piiDetectors": [{
        "id": "person-name", "entity": "PERSON", "type": "ner",
        "ner": {
            "model": "spacy:xx_ent_wiki_sm", "labels": ["PER"], "minScore": 0.8,
            "cascade": {"model": "gliner:aism/missing", "labels": ["person"], "minScore": 0.35},
        },
        "masking": _PERSON_MASK,
    }]}
    dets, errs = build_detectors(spec)
    assert errs and "Kaskade" in errs[0]
    assert all(d.id != "person-name" for d in dets)


def test_cascade_schema_and_regex_rejection(tmp_path):
    import yaml

    raw = yaml.safe_load(POLICY.read_text())
    person = next(d for d in raw["spec"]["piiDetectors"] if d["id"] == "person-name")
    person["ner"]["cascade"] = {
        "model": "gliner:urchade/gliner_multi_pii-v1", "labels": ["person"], "minScore": 0.35,
    }
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    load_policy(path, SCHEMA)

    person["ner"]["cascade"]["triggers"] = {"notATrigger": True}
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path, SCHEMA)

    raw = yaml.safe_load(POLICY.read_text())
    email = next(d for d in raw["spec"]["piiDetectors"] if d["id"] == "email")
    email["ner"] = {
        "model": "spacy:xx_ent_wiki_sm", "labels": ["PER"], "minScore": 0.5,
        "cascade": {"model": "gliner:urchade/gliner_multi_pii-v1", "labels": ["person"], "minScore": 0.35},
    }
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(PolicyError, match="nur bei type ner"):
        load_policy(path, SCHEMA)


def test_traceparent():
    tid, tp = trace.continue_or_start("00-" + "a" * 32 + "-" + "b" * 16 + "-01")
    assert tid == "a" * 32 and tp.split("-")[1] == tid and tp.split("-")[2] != "b" * 16
    tid2, _ = trace.continue_or_start("garbage")
    assert len(tid2) == 32
