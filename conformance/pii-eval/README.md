# PII-Erkennung: Messung auf synthetischen deutschen Daten

Stand: 2026-10-05. Gemessen wird die Erkennung des Gateway-Prototyps im AISM Reference Stack (S2) mit den
`piiDetectors` der Konformitäts-Testpolicy – derselbe Code wie im Gateway
(`aism_gateway.pii.Masker.resolve`, inkl. Überlappungsauflösung), Kontext `prompt`.

**Kurzfassung (ehrlich):** E-Mail, IBAN und die getesteten Secret-Formate werden auf diesen Daten
vollständig erkannt (regelbasiert, deterministisch). **Personennamen nicht:** auf dem Held-out-Set
bleiben mit jedem der drei getesteten spaCy-Modelle **14 % der Namen im Klartext** (Recall maskiert
0,86), v. a. kleingeschriebene Namen, alleinstehende Vornamen und seltenere Namen. Die Daten sind
klein, synthetisch und schablonenbasiert; reale Texte (Tippfehler, Kontext, andere Namen) sind
schwieriger. Die Zahlen sind daher **eine Obergrenze für diese Satzmuster, kein Qualitätsnachweis**.
M-12 (fail-closed bei Detektorausfall) schützt nicht vor *Fehlklassifikation* – Namen, die NER
nicht erkennt, gehen unmaskiert an S3–S6. Für Cloud-Egress ist das ein relevantes Restrisiko.

## Daten

| Datei | Inhalt |
|---|---|
| [`generate_dataset.py`](generate_dataset.py) | deterministischer Generator (Seeds 20261005 / 4711) |
| [`pii_eval_de.jsonl`](pii_eval_de.jsonl) | **Dev-Set**: 165 Sätze, 185 Entitäten (90 PERSON, 45 EMAIL, 30 IBAN, 20 SECRET), 25 Negativsätze (Orte, Firmen, Produkte, „Max.“, „frank und frei“, IBAN mit falscher Prüfziffer) |
| [`pii_eval_de_heldout.jsonl`](pii_eval_de_heldout.jsonl) | **Held-out-Set**: 73 Sätze, 80 Entitäten, andere Schablonen und Seed; erst *nach* den Korrekturen erzeugt und nur zum Messen verwendet |

Alle Werte sind synthetisch: zufällige Kombinationen gängiger Vor-/Nachnamen (inkl. ü/ö/ß,
türkischer und anderer Namen), E-Mail-Domains nach RFC 2606, IBANs mit gültiger mod-97-Prüfziffer
aus Zufallsziffern, Secrets in den Formaten `sk-…`, `AKIA…`, `ghp_…`. Anreden/Titel („Herr Dr.“)
gehören nicht zur annotierten Spanne.

## Metriken

- **Recall strikt** – vorhergesagte Spanne gleichen Typs mit identischen Grenzen.
- **Recall maskiert** – jedes Nicht-Leerzeichen der Gold-Spanne ist von *irgendeiner* Vorhersage
  überdeckt, d. h. der Wert verlässt S2 nicht im Klartext. **Datenschutzrelevante Kennzahl.**
- **teilweise** – nur teilweise überdeckt (ein Teil des Werts bleibt lesbar).
- **Präzision** – Anteil der Vorhersagen eines Typs, die eine Gold-Spanne gleichen Typs
  überlappen. False Positives (FP) bedeuten Über-Maskierung (Nutzwertverlust, kein Datenabfluss).

Modelle: `xx_ent_wiki_sm` 3.8.0 (Policy-Standard), `de_core_news_sm` 3.8.0 und
`de_core_news_md` 3.8.0 (Wheels von github.com/explosion/spacy-models, SHA-256
`fec69fec…a3e7` bzw. `b903f592…d0`), spaCy 3.8.16, CPU. `minScore` wird nicht angewendet
(spaCy-Kleinmodelle liefern keinen Score).

## Ergebnisse

**A) Dev-Set, Stand vor den Korrekturen** (165 Sätze; Entitäten: PERSON 90, EMAIL 45, IBAN 30, SECRET 20)

| Erkennung | Typ | n | Recall strikt | Recall maskiert | teilweise | Präzision | FP | ms/Satz |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| nur Regex/Prüfsumme | PERSON | 90 | 0.00 | 0.00 | 0 | – | 0 | 0.01 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.01 |
|  | IBAN | 30 | 0.83 | 0.83 | 0 | 1.00 | 0 | 0.01 |
|  | SECRET | 20 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.01 |
| Regex + `xx_ent_wiki_sm` | PERSON | 90 | 0.82 | 0.88 | 0 | 0.86 | 13 | 1.49 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.49 |
|  | IBAN | 30 | 0.83 | 0.83 | 0 | 1.00 | 0 | 1.49 |
|  | SECRET | 20 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.49 |
| Regex + `de_core_news_sm` | PERSON | 90 | 0.80 | 0.88 | 0 | 0.79 | 21 | 2.65 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 2.65 |
|  | IBAN | 30 | 0.83 | 0.83 | 0 | 1.00 | 0 | 2.65 |
|  | SECRET | 20 | 0.95 | 1.00 | 0 | 1.00 | 0 | 2.65 |
| Regex + `de_core_news_md` | PERSON | 90 | 0.86 | 0.89 | 1 | 0.88 | 11 | 3.03 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.03 |
|  | IBAN | 30 | 0.83 | 0.83 | 0 | 1.00 | 0 | 3.03 |
|  | SECRET | 20 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.03 |

**B) Dev-Set, nach den Korrekturen (optimistisch: Korrekturen wurden an diesem Set entwickelt)** (165 Sätze; Entitäten: PERSON 90, EMAIL 45, IBAN 30, SECRET 20)

| Erkennung | Typ | n | Recall strikt | Recall maskiert | teilweise | Präzision | FP | ms/Satz |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| nur Regex/Prüfsumme | PERSON | 90 | 0.22 | 0.22 | 0 | 1.00 | 0 | 0.02 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.02 |
|  | IBAN | 30 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.02 |
|  | SECRET | 20 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.02 |
| Regex + `xx_ent_wiki_sm` | PERSON | 90 | 0.89 | 0.94 | 0 | 0.87 | 13 | 1.84 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.84 |
|  | IBAN | 30 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.84 |
|  | SECRET | 20 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.84 |
| Regex + `de_core_news_sm` | PERSON | 90 | 0.86 | 0.93 | 0 | 0.80 | 21 | 2.73 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 2.73 |
|  | IBAN | 30 | 1.00 | 1.00 | 0 | 1.00 | 0 | 2.73 |
|  | SECRET | 20 | 0.95 | 1.00 | 0 | 1.00 | 0 | 2.73 |
| Regex + `de_core_news_md` | PERSON | 90 | 0.92 | 0.96 | 1 | 0.89 | 11 | 3.15 |
|  | EMAIL | 45 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.15 |
|  | IBAN | 30 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.15 |
|  | SECRET | 20 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.15 |

**C) Held-out-Set, nach den Korrekturen (maßgeblich)** (73 Sätze; Entitäten: PERSON 50, EMAIL 10, IBAN 15, SECRET 5)

| Erkennung | Typ | n | Recall strikt | Recall maskiert | teilweise | Präzision | FP | ms/Satz |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| nur Regex/Prüfsumme | PERSON | 50 | 0.20 | 0.20 | 0 | 1.00 | 0 | 0.02 |
|  | EMAIL | 10 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.02 |
|  | IBAN | 15 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.02 |
|  | SECRET | 5 | 1.00 | 1.00 | 0 | 1.00 | 0 | 0.02 |
| Regex + `xx_ent_wiki_sm` | PERSON | 50 | 0.72 | 0.86 | 0 | 0.96 | 2 | 1.47 |
|  | EMAIL | 10 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.47 |
|  | IBAN | 15 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.47 |
|  | SECRET | 5 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.47 |
| Regex + `de_core_news_sm` | PERSON | 50 | 0.70 | 0.86 | 0 | 0.83 | 9 | 3.21 |
|  | EMAIL | 10 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.21 |
|  | IBAN | 15 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.21 |
|  | SECRET | 5 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.21 |
| Regex + `de_core_news_md` | PERSON | 50 | 0.78 | 0.86 | 0 | 0.92 | 4 | 3.05 |
|  | EMAIL | 10 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.05 |
|  | IBAN | 15 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.05 |
|  | SECRET | 5 | 1.00 | 1.00 | 0 | 1.00 | 0 | 3.05 |

**D) Held-out-Set, Ablation ohne Titel-Regel** (73 Sätze; Entitäten: PERSON 50, EMAIL 10, IBAN 15, SECRET 5)

| Erkennung | Typ | n | Recall strikt | Recall maskiert | teilweise | Präzision | FP | ms/Satz |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Regex + `xx_ent_wiki_sm` (ohne `person-title`) | PERSON | 50 | 0.70 | 0.84 | 0 | 0.95 | 2 | 1.46 |
|  | EMAIL | 10 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.46 |
|  | IBAN | 15 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.46 |
|  | SECRET | 5 | 1.00 | 1.00 | 0 | 1.00 | 0 | 1.46 |
| Regex + `de_core_news_md` (ohne `person-title`) | PERSON | 50 | 0.76 | 0.84 | 0 | 0.91 | 4 | 2.87 |
|  | EMAIL | 10 | 1.00 | 1.00 | 0 | 1.00 | 0 | 2.87 |
|  | IBAN | 15 | 1.00 | 1.00 | 0 | 1.00 | 0 | 2.87 |
|  | SECRET | 5 | 1.00 | 1.00 | 0 | 1.00 | 0 | 2.87 |

## Gefundene Schwächen und Korrekturen

1. **IBAN gefolgt von Großbuchstaben-Token wurde nie erkannt** (Dev-Set A: 5/30 verfehlt, alle
   „… BIC COBADEFFXXX“). Ursache: das Muster `(?: ?[A-Z0-9]){11,30}` verschluckt das folgende
   Token; die Prüfziffer der zu langen Spanne schlägt fehl, der Kandidat wurde verworfen.
   **Korrektur** (`pii.py`, `Detector._checksum_end`): bei Prüfsummen-Detektoren wird die längste
   prüfziffergültige Teilspanne gesucht, die an einer Token-Grenze endet. Danach 30/30 bzw. 15/15.
2. **Namen nach Anrede/Titel** („Frau Müller“, „Herr Dr. Braun“) verfehlen alle Modelle häufig.
   **Ergänzung**: Regex-Detektor `person-title` in den Policies (maskiert per benannter Gruppe
   `(?P<pii>…)` nur den Namen; neue Policy-Format-Regel). Effekt auf dem Held-out-Set klein
   (0,84 → 0,86), da dort wenige Anreden vorkommen; auf dem Dev-Set größer, aber dort entwickelt.
3. **Nicht korrigiert:** kleingeschriebene Namen („ines wagner“), alleinstehende Vornamen
   („Danke Max!“, „Moritz sagt …“), seltene Namen („Ülkü“), Über-Maskierung großgeschriebener
   Satzanfänge („Meine Adresse“, „Wer“, „Schick“, „Leite“) und Produktnamen („Teams“).

## Bewertung und Empfehlung

- Für **lokale Inferenz** (S6 im eigenen Netz) ist die Restquote ein vertretbares,
  dokumentiertes Risiko; für **Cloud-Egress** nicht ohne Weiteres. Die Referenz-Policy erlaubt
  Cloud-Fallback daher nur für `public`/`internal` ohne erkannte Entitäten – ein *nicht erkannter*
  Name fällt aber genau in diese Klasse. Betreiber SOLLTEN Cloud-Egress nur mit einem auf eigenen
  Daten gemessenen Detektor freigeben oder auf Rollen/Anwendungsfälle ohne Personenbezug begrenzen.
- `de_core_news_md` ist auf dem Held-out-Set beim strikten Recall leicht besser (0,78 vs. 0,72),
  beim datenschutzrelevanten Recall gleichauf (0,86) und ≈ 2× langsamer. Ein Modellwechsel allein
  löst das Problem nicht; nächste Schritte wären ein größeres Modell (`de_core_news_lg`, Transformer)
  oder ein dediziertes PII-Modell, Gazetteers für Vornamen und eine Messung auf echten,
  pseudonymisierten Betriebsdaten.

## Reproduzieren

```bash
python3 conformance/pii-eval/generate_dataset.py
pip install <de_core_news_sm/md-Wheels>      # optional, zusätzlich zu xx_ent_wiki_sm
python3 conformance/pii-eval/evaluate.py --ner none --ner spacy:xx_ent_wiki_sm \
  --ner spacy:de_core_news_sm --ner spacy:de_core_news_md --out results-dev.json
python3 conformance/pii-eval/evaluate.py --data conformance/pii-eval/pii_eval_de_heldout.jsonl \
  --ner none --ner spacy:xx_ent_wiki_sm --ner spacy:de_core_news_sm --ner spacy:de_core_news_md --out results-heldout.json
```

Ergebnisdateien: `results-v0-before-fixes.json` (A), `results-dev.json` (B), `results-heldout.json`
(C), `results-heldout-no-title-rule.json` (D) – jeweils mit allen Fehltreffern (`misses`) und
False Positives.
