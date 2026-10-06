# PII-Erkennung: Messung auf synthetischen deutschen Daten

Stand: 2026-10-06. Gemessen wird die Erkennung des Gateway-Prototyps im AISM Reference Stack (S2) mit den
`piiDetectors` der Konformitäts-Testpolicy – derselbe Code wie im Gateway
(`aism_gateway.pii.Masker.resolve`, inkl. Überlappungsauflösung), Kontext `prompt`.

**Kurzfassung (ehrlich):** E-Mail, IBAN und die getesteten Secret-Formate werden auf diesen Daten
vollständig maskiert (regelbasiert, deterministisch). **Personennamen nicht.**

Der früher veröffentlichte Wert **0,86** maskierter Recall gilt für das **alte** Held-out-Set
(50 Namen, Regex plus spaCy, ohne Gazetteer). Dieselbe Datei, nachträglich mit dem neuen Standard
gemessen und nicht zum Abstimmen der Regeln verwendet: **0,94**.

Maßgeblich ist das **neue** Held-out-Set v2. Es wurde erst erzeugt, nachdem die Regeln auf dem
erweiterten Dev-Set festlagen, und ist absichtlich härter (andere Schablonen, disjunkte Namen,
Kontextformeln, die der Detektor nicht kennt). Dort liegt der alte Detektor bei **0,594** und der
neue Standard (Gazetteer plus `spacy:xx_ent_wiki_sm`) bei **0,703** maskiert, Präzision 0,868,
etwa 1,5 ms/Satz. Rund 30 % der Namen bleiben im Klartext. Das CI-Gate
([`gate.json`](gate.json)) steht auf diesem Wert, nicht auf 0,86: 0,86 wäre auf v2 eine Senkung
der Latte. Die 0,94 auf dem alten Set sind kein Ersatz für die 0,70 auf dem neuen.

Die Daten sind klein, synthetisch und schablonenbasiert. Reale Texte sind nicht gemessen und
schwieriger. Die Zahlen sind **eine Obergrenze für diese Satzmuster, kein Qualitätsnachweis**.
M-12 (fail-closed bei Detektorausfall) schützt nicht vor Fehlklassifikation. Für Cloud-Egress
bleibt ein nicht erkannter Name ein Restrisiko.

Optional, nicht im Standard-Image: eine Kaskade lässt Gazetteer plus `xx_ent_wiki_sm` immer
laufen und `urchade/gliner_multi_pii-v1` nur auf verdächtigen Sätzen (Abschnitt H). Auf v2 steigt
der maskierte Personen-Recall von 0,703 auf 0,969, auf dem vorher eingefrorenen Held-out v3 von
0,734 auf 1,000. Die mittlere Latenz liegt dort bei 49–55 ms/Satz, weil etwa 60 % der Sätze das
schwere Modell auslösen. Das CI-Gate 0,703 bleibt unverändert; die Kaskade hat eigene Gates.

## Daten

| Datei | Inhalt |
|---|---|
| [`generate_dataset.py`](generate_dataset.py) | deterministischer Generator (Seeds 20261005 / 4711 für die ersten Dateien; 20261006 für die Dev-Erweiterung `dx-*`; 424242 für Held-out v2 `h2-*`; 20261007 für Held-out v3 `h3-*`) |
| [`pii_eval_de.jsonl`](pii_eval_de.jsonl) | **Dev-Set**: die ursprünglichen 165 Sätze (unverändert) plus 71 Sätze Erweiterung. Zusammen 236 Sätze, 241 Entitäten (146 PERSON, 45 EMAIL, 30 IBAN, 20 SECRET). Die Erweiterung trägt `oov` |
| [`pii_eval_de_heldout.jsonl`](pii_eval_de_heldout.jsonl) | **Held-out v1**: 73 Sätze, 80 Entitäten. Historische Messung 0,86. Nicht zum Abstimmen der Gazetteer-Regeln verwendet |
| [`pii_eval_de_heldout_v2.jsonl`](pii_eval_de_heldout_v2.jsonl) | **Held-out v2 (maßgeblich für den Standard)**: 94 Sätze, 88 Entitäten (64 PERSON, 8 EMAIL, 12 IBAN, 4 SECRET), davon 41 mit `oov: true`. Namen und Schablonen disjunkt zur Dev-Erweiterung |
| [`pii_eval_de_heldout_v3.jsonl`](pii_eval_de_heldout_v3.jsonl) | **Held-out v3 (eingefroren vor dem Abstimmen der Kaskade)**: 94 Sätze, 88 Entitäten (64 PERSON, 8 EMAIL, 12 IBAN, 4 SECRET), davon 43 mit `oov: true`. Namen disjunkt zu Dev, v1 und v2. Prüfsumme [`pii_eval_de_heldout_v3.sha256`](pii_eval_de_heldout_v3.sha256) |

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

**C) Held-out v1, nach den Korrekturen von 2026-10-05 (historisch, nicht mehr das CI-Gate)** (73 Sätze; Entitäten: PERSON 50, EMAIL 10, IBAN 15, SECRET 5)

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

## Messung 2026-10-06 (Gazetteer, deutsche spaCy-Modelle, GLiNER)

Profile tauschen nur die Personen-Detektoren. `before` ist der Stand von Abschnitt C: `person-title` plus `spacy:xx_ent_wiki_sm`, ohne Gazetteer. `policy` ist die Datei unverändert und entspricht `gaz-xx`.

Auswahl **vor** dem Blick auf v2, auf dem erweiterten Dev-Set: EMAIL/IBAN/SECRET maskiert müssen 1,0 bleiben, Personen-Präzision mindestens etwa 0,85, und eine neue schwere Abhängigkeit nur, wenn der Gewinn gegen `gaz-xx` mindestens 0,03 maskierten Recall bringt. `de_core_news_md` lag darunter (+0,021). `de_core_news_lg` ist mehrere hundert Megabyte, senkt auf dem Dev-Set den strikten SECRET-Recall auf 0,95 (maskiert bleibt 1,0) und ist auf v2 nicht durchgängig besser als `md`. GLiNER (`urchade/gliner_multi_pii-v1`, Label `person`, `minScore` 0,35) erreicht maskiert 1,00 inklusive unbekannter Namen, braucht aber torch und etwa 80–95 ms/Satz. **Standard bleibt Gazetteer (Paare plus Kontext-Preset `de`) plus `spacy:xx_ent_wiki_sm`.** Das Modell liegt schon im Image. Nach v2 wurde daran nichts geändert, auch nicht an den Kontextformeln, die v2 absichtlich unbekannt lässt (`i. V.`, `Gezeichnet`, `Ich bin`, `Ansprechpartner`, `Könntest du`).

Latenz: ein frischer Prozess je Profil, CPU, ein Satz nach dem anderen, Modell vor der Schleife geladen, kein separates Warmup. Die Millisekunden schwanken zwischen Läufen; der Recall nicht. `person_by_vocab` auf dem Dev-Set zählt nur die 56 PERSON-Spannen der Erweiterung (`dx-*`, 23 in der Liste, 33 außerhalb), nicht die ursprünglichen 90.

**E) Erweitertes Dev-Set, Auswahlmenge** (236 Sätze; PERSON 146, EMAIL 45, IBAN 30, SECRET 20). EMAIL/IBAN/SECRET maskiert 1,0 und Präzision 1,0, außer: `spacy-lg` und `gaz-lg` SECRET strikt 0,950 (maskiert 1,0); `gliner` und `gaz-gliner` EMAIL strikt 0,933 (maskiert 1,0).

| Profil | R strikt | R maskiert | teilweise | Präzision | FP | ms/Satz | in Liste | außerhalb |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| before | 0.747 | 0.849 | 1 | 0.874 | 18 | 1.83 | 0.913 | 0.545 |
| spacy-md | 0.788 | 0.890 | 2 | 0.886 | 17 | 3.68 | 0.913 | 0.697 |
| spacy-lg | 0.767 | 0.918 | 0 | 0.887 | 17 | 3.72 | 0.913 | 0.788 |
| pairs | 0.562 | 0.562 | 0 | 1.000 | 0 | 0.02 | 0.609 | 0.152 |
| context | 0.452 | 0.452 | 0 | 1.000 | 0 | 0.06 | 0.870 | 0.636 |
| gazetteer | 0.740 | 0.740 | 0 | 1.000 | 0 | 0.04 | 1.000 | 0.636 |
| **gaz-xx (Standard)** | **0.801** | **0.904** | **0** | **0.880** | **18** | **1.53** | **1.000** | **0.697** |
| gaz-md | 0.822 | 0.925 | 2 | 0.890 | 17 | 3.63 | 1.000 | 0.788 |
| gaz-lg | 0.788 | 0.938 | 0 | 0.890 | 17 | 3.89 | 1.000 | 0.818 |
| gliner | 0.774 | 1.000 | 0 | 0.874 | 21 | 94.97 | 1.000 | 1.000 |
| gaz-gliner | 0.774 | 1.000 | 0 | 0.874 | 21 | 88.37 | 1.000 | 1.000 |

Das Gazetteer allein hat auf diesem Set 0 False Positives. Die 18 FP von `gaz-xx` sind dieselben wie bei `before` (spaCy: „Wer“, „Meine Adresse“, „Herr Dr“, „Max“ und weitere Satzanfänge). Quelle: [`results-dev-isolated.json`](results-dev-isolated.json).

**F) Held-out v2, Berichtsmenge** (94 Sätze; PERSON 64, EMAIL 8, IBAN 12, SECRET 4). EMAIL, IBAN und SECRET: Recall maskiert 1,0 und Präzision 1,0 in jedem Profil. `policy` wurde separat geprüft und trifft `gaz-xx` (0,703).

| Profil | R strikt | R maskiert | teilweise | Präzision | FP | ms/Satz | in Liste | außerhalb |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| before | 0.375 | 0.594 | 0 | 0.844 | 7 | 1.68 | 0.652 | 0.561 |
| spacy-md | 0.406 | 0.734 | 0 | 0.922 | 4 | 4.76 | 0.826 | 0.683 |
| spacy-lg | 0.375 | 0.609 | 0 | 0.867 | 6 | 3.98 | 0.565 | 0.634 |
| pairs | 0.234 | 0.250 | 1 | 1.000 | 0 | 0.02 | 0.478 | 0.122 |
| context | 0.328 | 0.328 | 0 | 1.000 | 0 | 0.03 | 0.609 | 0.171 |
| gazetteer | 0.391 | 0.406 | 1 | 1.000 | 0 | 0.04 | 0.826 | 0.171 |
| **gaz-xx / policy** | **0.484** | **0.703** | **1** | **0.868** | **7** | **1.51** | **0.913** | **0.585** |
| gaz-md | 0.406 | 0.734 | 0 | 0.922 | 4 | 3.94 | 0.826 | 0.683 |
| gaz-lg | 0.484 | 0.734 | 0 | 0.887 | 6 | 4.28 | 0.826 | 0.683 |
| gliner | 0.828 | 1.000 | 0 | 0.877 | 9 | 81.79 | 1.000 | 1.000 |
| gaz-gliner | 0.812 | 1.000 | 0 | 0.877 | 9 | 81.49 | 1.000 | 1.000 |

Quelle: [`results-heldout-v2.json`](results-heldout-v2.json). CI-Schwelle: PERSON `recall_masked` ≥ 0,703, EMAIL/IBAN/SECRET ≥ 1,0, Profil `policy`.

**G) Held-out v1, nur nachgemessen** (nicht zum Tunen, nicht das Gate). `before` trifft den veröffentlichten Wert 0,86.

| Profil | R strikt | R maskiert | Präzision | FP | ms/Satz |
|---|---:|---:|---:|---:|---:|
| before | 0.720 | 0.860 | 0.956 | 2 | 2.25 |
| gazetteer | 0.840 | 0.840 | 1.000 | 0 | 0.06 |
| gaz-xx | 0.800 | 0.940 | 0.959 | 2 | 1.70 |
| gaz-md | 0.900 | 0.980 | 0.925 | 4 | 5.22 |
| gaz-lg | 0.900 | 1.000 | 1.000 | 0 | 5.28 |
| gliner | 0.800 | 1.000 | 0.962 | 2 | 80.47 |

## Messung 2026-10-06 (Kaskade)

Die Trigger und die GLiNER-Schwelle der Kaskade (`minScore` 0,55) wurden nur auf dem Dev-Set
festgelegt. Held-out v2 und v3 wurden dafür nicht verwendet. v3 (Seed 20261007) lag schon fest,
bevor diese Wahl getroffen wurde. Das Profil `gliner` bleibt bei `minScore` 0,35, damit die
älteren Tabellen vergleichbar bleiben. `listedGivenName` ist aus: auf dem Dev-Set hob der Trigger
den maskierten Recall nur um etwa 0,013 und steigerte die Auslöserate von 0,366 auf 0,582.

Die drei Profile unten sind in getrennten Prozessen mit derselben Uhr gemessen (`Masker.resolve`
je JSONL-Zeile). Die Millisekunden der Abschnitte E–G stammen aus einem anderen Lauf und bleiben
dort stehen. p95 ist der Nearest-Rank-Wert (`ceil(0,95·n) − 1`). Die Auslöserate zählt geteilte
Sätze, nicht JSONL-Zeilen (v2: 104 Sätze auf 94 Zeilen, v3: 109 auf 94). EMAIL, IBAN und SECRET
sind in jedem Lauf maskiert 1,0 bei Präzision 1,0.

**H) Standard, nur GLiNER, Kaskade** (Quelle: [`results-cascade-heldout.json`](results-cascade-heldout.json))

| Menge | Profil | PERSON maskiert | Präzision | FP | Mittel ms | p95 ms | Auslöser |
|---|---|---:|---:|---:|---:|---:|---:|
| v1 (73 Sätze, 50 PERSON) | gaz-xx | 0.940 | 0.959 | 2 | 1.50 | 1.95 | – |
|  | gliner | 1.000 | 0.962 | 2 | 63.73 | 75.62 | – |
|  | cascade | 0.980 | 0.961 | 2 | 42.10 | 79.32 | 0.589 |
| v2 (94 Sätze, 64 PERSON) | gaz-xx | 0.703 | 0.868 | 7 | 1.40 | 1.75 | – |
|  | gliner | 1.000 | 0.877 | 9 | 68.85 | 89.45 | – |
|  | cascade | 0.969 | 0.886 | 8 | 49.22 | 94.06 | 0.615 |
| v3 (94 Sätze, 64 PERSON) | gaz-xx | 0.734 | 0.746 | 16 | 1.49 | 1.81 | – |
|  | gliner | 1.000 | 0.901 | 7 | 75.41 | 105.53 | – |
|  | cascade | 1.000 | 0.780 | 18 | 54.96 | 115.11 | 0.679 |

Auf v2 bleibt der Listen-Recall der Kaskade bei 0,913 (wie `gaz-xx`); die 41 Namen außerhalb der
Liste sind vollständig maskiert. Auf v3 sind beide Gruppen bei 1,000 (Gazetteer: 0,905 in der
Liste, 0,651 außerhalb).

Grenzen, die nach dieser Messung so bleiben:

- Einzelne Vornamen aus dem Wortlexikon ohne Cue gehen weiter durch, solange `listedGivenName`
  aus ist. Auf v1 fehlt „Svetlana“, auf v2 fehlen „Hannah“ und „Lena“ (beide in der Liste).
  Kleingeschriebene Einzel-Tokens und Paare, deren beide Teile häufige Wörter sind, lösen die
  Kaskade ebenfalls nicht aus.
- Die Vereinigung übernimmt die False Positives des schnellen Modells. Auf v3 liegt die
  Personen-Präzision der Kaskade bei 0,780 (18 FP), unter nur-GLiNER (0,901, 7 FP).
- `lowConfidence` hat auf v1, v2 und v3 null Sätze ausgelöst. Die Beam-Margen von
  `xx_ent_wiki_sm` liegen bei den Primärtreffern nahe 1.
- Das Wortlexikon ist Untertitel-Häufigkeit, keine Nomenliste. Namen, die zugleich häufige
  Wörter sind („König“, „Wolf“, „Müller“), sehen für den Trigger nicht unbekannt aus.
- Die Auslöserate hängt vom Text ab. Diese Sätze sind namensdicht; 0,59–0,68 ist keine Zusage
  für Betriebspost. Der p95 liegt nahe am Nur-GLiNER-Lauf, weil ein ausgelöster Satz beide
  Modelle bezahlt. Gespart wird der Mittelwert über die Sätze ohne Verdacht.
- Ist `ner.cascade` gesetzt und das Sekundärmodell nicht ladbar oder zur Laufzeit ausgefallen,
  antwortet das Gateway mit 503. Es gibt keinen stillen Rückfall auf das schnelle Modell.
- Die Kaskade ist im Beispiel und in der Konformitätspolicy aus. Das Standard-Image enthält
  kein torch. `INSTALL_GLINER=1` ist eine optionale Image-Variante und nicht der
  reproduzierbare, hash-gesperrte Build.

CI: [`gate.json`](gate.json) bleibt bei PERSON 0,703 (Profil `policy` auf v2).
[`gate-cascade-v2.json`](gate-cascade-v2.json) verlangt PERSON 0,969,
[`gate-cascade-v3.json`](gate-cascade-v3.json) PERSON 1,000, jeweils EMAIL/IBAN/SECRET 1,0.
Job `pii-cascade` in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), lokal
`tools/ci-local.sh pii-cascade` (nicht Teil von `all`).

### Vorher / nachher

| Menge | Detektor | PERSON maskiert | Präzision | FP | ms/Satz |
|---|---|---:|---:|---:|---:|
| Held-out v1 | before (veröffentlicht) | 0.860 | 0.956 | 2 | 2.25 |
| Held-out v1 | gaz-xx | 0.940 | 0.959 | 2 | 1.70 |
| Held-out v2 | before | 0.594 | 0.844 | 7 | 1.68 |
| Held-out v2 | gaz-xx (Standard, CI-Gate) | 0.703 | 0.868 | 7 | 1.51 |

Was weiterhin durchrutscht: Namen, die nicht in den Listen stehen und keinen starken Kontext haben (kleingeschrieben im Fließtext, alleinstehende Vornamen wie Ülkü, Ines, Chinedu, Sabine). Listen-Namen mit Paar oder Cue liegen auf v2 bei 0,913 maskiert. Das Gazetteer allein ist präzise (v2: 0 FP) und schwach im Recall (0,406). Größere spaCy-Modelle sind nicht einheitlich besser: `de_core_news_lg` allein liegt auf v2 bei 0,609, unter `md` (0,734). GLiNER ist die Qualitätsoption und zu schwer für den Image-Standard.

Die Listen (5921 Vornamen, 1998 Nachnamen, Stand 2026-10-06) sind Häufigkeitslisten, kein Register. „Mustermann“ fehlt; Erika und Max Mustermann maskiert weiterhin spaCy, das die Konformitätssuite braucht. Lizenzen: [`../../gateway/aism_gateway/data/README.md`](../../gateway/aism_gateway/data/README.md).

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
3. **Gazetteer (2026-10-06), auf der Dev-Erweiterung entwickelt, nicht auf Held-out v1 oder v2:**
   Paare unabhängig von der Großschreibung („anna müller“), starke Cues auch für unbekannte
   Namen („mein Name ist …“, Signatur, Grußformel) und schwache Cues nur für gelistete Tokens
   („Danke, Max!“, „Anna sagt“, „Liebe Anna“). „Mein Name ist im Telefonbuch“, „Hallo zusammen“,
   „Max. 5 Geräte“ und „frank und frei“ bleiben unmaskiert. **Nicht gelöst:** unbekannte Namen
   ohne starken Cue, und die spaCy-False-Positives an Satzanfängen. Die Kontextformeln, die nur
   in v2 vorkommen, wurden nach der Messung nicht nachgetragen.

## Bewertung und Empfehlung

- Für **lokale Inferenz** (S6 im eigenen Netz) ist die Restquote ein vertretbares,
  dokumentiertes Risiko; für **Cloud-Egress** nicht ohne Weiteres. Die Referenz-Policy erlaubt
  Cloud-Fallback daher nur für `public`/`internal` ohne erkannte Entitäten – ein *nicht erkannter*
  Name fällt aber genau in diese Klasse. Betreiber SOLLTEN Cloud-Egress nur mit einem auf eigenen
  Daten gemessenen Detektor freigeben oder auf Rollen/Anwendungsfälle ohne Personenbezug begrenzen.
- Der Standard ist Gazetteer plus `xx_ent_wiki_sm` (Abschnitt F: 0,703 maskiert auf v2, etwa 1,5 ms).
  `de_core_news_md` mit Gazetteer liegt auf v2 bei 0,734 und etwa 4 ms, ist aber nicht im Image.
  `de_core_news_lg` ist auf v2 nicht besser als `md` und auf dem Dev-Set beim strikten SECRET-Recall
  schlechter. GLiNER ist über `ner.model` zuschaltbar (`gliner:urchade/gliner_multi_pii-v1`,
  Labels `person`, `minScore` 0,35): auf v2 maskiert 1,00 bei etwa 82 ms/Satz. Dieselbe
  Erkennung als `ner.cascade` (Abschnitt H, Schwelle 0,55) erreicht auf v2 0,969 und auf v3
  1,000 maskiert, bei 49–55 ms Mittelwert auf diesen Sätzen, und bleibt aus, solange die Policy
  sie nicht setzt. Eine Messung auf echten, pseudonymisierten Betriebsdaten fehlt.

## Reproduzieren

```bash
python3 conformance/pii-eval/generate_dataset.py   # schreibt Dev, v1, v2 und v3 neu; Seeds sind fest
python3 conformance/pii-eval/evaluate.py \
  --data conformance/pii-eval/pii_eval_de_heldout_v2.jsonl \
  --profile policy --gate conformance/pii-eval/gate.json --no-misses
# Varianten: --profile before|spacy-md|spacy-lg|pairs|context|gazetteer|gaz-xx|gaz-md|gaz-lg|gliner|gaz-gliner|cascade
# de_core_news_md/lg und GLiNER (torch, transformers) sind nicht im Gateway-Image.
# Kaskade (nach pip install -r gateway/requirements-gliner.txt), je ein frischer Prozess:
python3 conformance/pii-eval/evaluate.py \
  --data conformance/pii-eval/pii_eval_de_heldout_v2.jsonl \
  --profile cascade --gate conformance/pii-eval/gate-cascade-v2.json --no-misses
python3 conformance/pii-eval/evaluate.py \
  --data conformance/pii-eval/pii_eval_de_heldout_v3.jsonl \
  --profile cascade --gate conformance/pii-eval/gate-cascade-v3.json --no-misses
```

`tools/ci-local.sh pii` prüft nur das Profil `policy` gegen [`gate.json`](gate.json).
`tools/ci-local.sh pii-cascade` prüft die Kaskade auf v2 und v3 und die Prüfsumme von v3.
v3 nach der Messung nicht umschreiben, um ein Gate zu treffen.

Ergebnisdateien der Messung von 2026-10-05: `results-v0-before-fixes.json` (A), `results-dev.json` (B),
`results-heldout.json` (C), `results-heldout-no-title-rule.json` (D).
Messung 2026-10-06: `results-dev-isolated.json` (E), `results-heldout-v2.json` (F),
`results-heldout-v1-remeasure.json` (G). `results-dev-variants.json` ist ein früherer gemeinsamer
Lauf mit Fehltreffern; die Millisekunden darin sind verzerrt, weil das erste Profil den Prozess
aufwärmt. Die Tabellen nutzen die isolierten Läufe.
