# Built-in German name lists

Loaded by a policy detector `type: gazetteer` with `givenNames: builtin:de-given` and
`surnames: builtin:de-surnames` (see `policy/AISM-Policy-Format.md` §4.4).

One name per line, UTF-8. Lookup is case-insensitive (`str.casefold`). The lists are a
**reference gazetteer**, not a population register. Names that are not on the list are only
masked when a context rule or an NER model matches them. Rebuild with
[`tools/build_name_gazetteer.py`](../../../tools/build_name_gazetteer.py) (network required).
The files in this directory were generated on 2026-10-06.

## Sources and licences

| File | What was taken | Source | Licence |
|---|---|---|---|
| `de_given_names.txt` | Cologne given names with frequency ≥ 2 | [fxnn/vornamen](https://github.com/fxnn/vornamen) (`vornamen-grouped-sorted.dat`), Stadt Köln, 19 Jan 2018 | CC BY 3.0 DE. Attribution: Stadt Köln, via https://github.com/fxnn/vornamen |
| `de_given_names.txt` | about 1 000 modern given names | [ndsvw/JSON-Namen](https://github.com/ndsvw/JSON-Namen) `vornamen_m.json`, `vornamen_w.json` | MIT |
| `de_given_names.txt` | Germanic-origin given names of length ≥ 4 | [PenTestical/german_names](https://github.com/PenTestical/german_names) `2000_german_firstnames.txt` | MIT |
| `de_given_names.txt` | popular given names, country DE | [sigpwned/popular-names-by-country-dataset](https://github.com/sigpwned/popular-names-by-country-dataset) | CC0 |
| `de_surnames.txt` | 2 000 common surnames | [ndsvw/JSON-Namen](https://github.com/ndsvw/JSON-Namen) `nachnamen.json` | MIT |
| `de_surnames.txt` | most common surnames (short list) | [PenTestical/german_names](https://github.com/PenTestical/german_names) `most_common_german_surnames.txt` | MIT |
| `de_surnames.txt` | popular surnames, country DE | [sigpwned/popular-names-by-country-dataset](https://github.com/sigpwned/popular-names-by-country-dataset) | CC0 |

Entries shorter than 3 characters (4 for the Germanic-origin given-name list) and a small
function-word stoplist are dropped. No names were added by hand to chase evaluation misses.
