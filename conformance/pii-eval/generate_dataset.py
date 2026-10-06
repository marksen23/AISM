#!/usr/bin/env python3
"""Generates a small SYNTHETIC German PII evaluation set (deterministic, seed 20261005).

All names are random combinations of common German (and a few other) first and last names; e-mail
addresses use reserved domains (example.com/.org/.net, RFC 2606); IBANs are synthetic with a valid
mod-97 check digit; secrets are random strings in common key formats. No real persons or accounts.
Output:
  pii_eval_de.jsonl            dev set (original templates, seed 20261005) plus an appended
                               extension (seed 20261006, ids dx-*) used to develop the gazetteer
  pii_eval_de_heldout.jsonl    first held-out set (seed 4711); not used to tune the 2026-10-06 detectors
  pii_eval_de_heldout_v2.jsonl fresh held-out set (seed 424242, other templates and a disjoint
                               out-of-gazetteer name list); measured only after the detector was frozen
  pii_eval_de_heldout_v3.jsonl held-out set for the NER cascade (seed 20261007). Written and frozen
                               before cascade triggers were tuned. Disjoint names, mix of in-list and
                               OOV, varied cues. Do not tune detectors on this file or on v2.
Format: {"id", "text", "entities": [{"start","end","type","value"}], "tags"}
"""
import json
import pathlib
import random
import string

R = random.Random(20261005)
FIRST = ["Anna", "Lukas", "Sophie", "Jonas", "Marie", "Felix", "Laura", "Paul", "Lea", "Tim", "Hannah", "Moritz",
         "Katharina", "Jan-Hendrik", "Ülkü", "Mehmet", "Svetlana", "Giulia", "Björn", "Ines", "Frank", "Peter",
         "Sabine", "Jürgen", "Ayşe", "Dimitrios", "Karl-Heinz", "Lena", "Max", "Emma"]
LAST = ["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker", "Schulz", "Hoffmann",
        "Koch", "Richter", "Klein", "Wolf", "Schröder", "Neumann", "Schwarz", "Zimmermann", "Braun", "Krüger",
        "Hartmann", "Lange", "Werner", "Krause", "Lehmann", "Yılmaz", "Kowalski", "Nguyen", "Großmann", "Öztürk"]
DOMAINS = ["example.com", "example.org", "example.net", "mail.example.com", "firma.example"]
TITLES = ["Herr", "Frau", "Herr Dr.", "Frau Dr.", "Prof."]


def person(kind):
    """Returns (unannotated prefix, annotated name). Titles (Herr/Frau/Dr.) are not part of the PII span."""
    f, l = R.choice(FIRST), R.choice(LAST)
    return {"full": ("", f"{f} {l}"), "title_last": (R.choice(TITLES) + " ", l), "first": ("", f),
            "title_full": (R.choice(TITLES) + " ", f"{f} {l}"), "lower": ("", f"{f} {l}".lower())}[kind]


def email():
    f, l = R.choice(FIRST), R.choice(LAST)
    tr = str.maketrans({"ü": "ue", "ö": "oe", "ä": "ae", "ß": "ss", "ı": "i", "ş": "s", "Ü": "Ue", "Ö": "Oe"})
    local = R.choice([f"{f}.{l}", f"{f[0]}.{l}", f"{l}{R.randint(1, 99)}", f"{f}_{l}"]).translate(tr).lower()
    return f"{local}@{R.choice(DOMAINS)}"


def iban(country="DE", spaced=None):
    lens = {"DE": 18, "AT": 16, "CH": 17}
    bban = "".join(R.choice(string.digits) for _ in range(lens[country]))
    num = int("".join(str(int(c, 36)) for c in bban + country + "00"))
    s = f"{country}{98 - num % 97:02d}{bban}"
    spaced = R.random() < 0.5 if spaced is None else spaced
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4)) if spaced else s


def bad_iban():
    s = iban(spaced=False)
    d = (int(s[3]) + 1) % 10
    return s[:3] + str(d) + s[4:]


def secret():
    k = R.choice(["sk", "akia", "ghp"])
    if k == "sk":
        return "sk-" + "".join(R.choice(string.ascii_letters + string.digits) for _ in range(32))
    if k == "akia":
        return "AKIA" + "".join(R.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return "ghp_" + "".join(R.choice(string.ascii_letters + string.digits) for _ in range(36))


T_PERSON = [
    ("Bitte rufe {P:full} wegen des Tickets INC-2026-0042 zurück.", "full"),
    ("{P:full} hat gestern den Drucker im 3. Stock gemeldet.", "full"),
    ("Kannst du {P:title_last} sagen, dass der Termin verschoben ist?", "title_last"),
    ("Laut {P:title_full} ist der Server seit Montag instabil.", "title_full"),
    ("Hallo zusammen, {P:first} kümmert sich heute um die Rufbereitschaft.", "first"),
    ("Viele Grüße\n{P:full}\nIT-Service", "full"),
    ("ich hab mit {P:lower} gesprochen, die vpn verbindung geht wieder", "lower"),
    ("Der Antrag von {P:full} und {P:full} liegt noch bei der Personalabteilung.", "full"),
    ("Wer ist der Vorgesetzte von {P:title_last}?", "title_last"),
    ("Die Rechnung wurde von {P:full} freigegeben.", "full"),
    ("Schick das bitte an {P:first}, nicht an {P:first}.", "first"),
    ("Im Meeting waren {P:full}, {P:full} und ich.", "full"),
]
T_EMAIL = ["Meine Adresse ist {E}, bitte dorthin antworten.", "Kontakt: {E}", "Leite die Mail an {E} weiter.",
           "Die Benachrichtigung ging an {E} und {E}.", "<{E}> schrieb: Das Passwort-Reset funktioniert nicht."]
T_IBAN = ["Bitte überweise auf {I}.", "IBAN: {I}", "Die Erstattung geht an {I} (Kontoinhaber siehe Akte).",
          "Neue Bankverbindung {I} ab dem 1. November.", "Konto {I} BIC COBADEFFXXX"]
T_SECRET = ["Der API-Key lautet {S}, bitte nicht weitergeben.", "export OPENAI_API_KEY={S}",
            "Im Log steht der Token {S} im Klartext."]
T_MIXED = ["{P:full} ({E}) möchte die Erstattung auf {I} erhalten.",
           "Von: {P:full} <{E}>\nBetreff: Zugang\nMein Key {S} geht nicht.",
           "{P:title_last} bittet um Rückruf, Mail: {E}."]
NEGATIVE = [
    "Der Server in Frankfurt am Main ist seit Montag wieder erreichbar.",
    "Bitte bestelle zwei Lizenzen für Microsoft Office bei der Deutschen Telekom.",
    "Das Meeting findet im Raum Berlin im 2. OG statt.",
    "Die Ticketnummer ist INC-2026-0042, Priorität hoch.",
    "Max. 5 Geräte pro Benutzer sind erlaubt.",
    "Wir haben frank und frei über das Budget gesprochen.",
    "Die Siemens-Anlage in München meldet einen Fehler.",
    "Bitte installiere Python 3.12 und Docker auf dem Build-Server.",
    "Der Zug der Deutschen Bahn nach Hamburg hatte Verspätung.",
    "Kostenstelle 4711, Projekt Phoenix, Release 2.3.1.",
    "Die Kollegen aus Wien und Zürich nehmen per Video teil.",
    "Das Handbuch liegt im SharePoint unter Richtlinien/IT-Sicherheit.",
    "Der Drucker HP LaserJet im Flur druckt nur noch leere Seiten.",
    "Ein kleiner Fehler im Weber-Grill-Rezept, nicht so wichtig.",
    "Die Firma Müller GmbH hat das Angebot angenommen.",
    "Bitte prüfe die Konfiguration von Kubernetes und Grafana.",
    "Am Freitag ist der Standort Köln geschlossen.",
    "Die Referenz DE00 1234 5678 ist keine gültige Kontonummer.",
    "Bitte nutze das Wiki statt E-Mail für Dokumentation.",
    "Das Modell Qwen läuft lokal auf der GPU.",
]


def fill(tpl, tags):
    text, ents, i = "", [], 0
    import re
    for m in re.finditer(r"\{(P:\w+|E|I|S)\}", tpl):
        text += tpl[i:m.start()]
        slot = m.group(1)
        if slot.startswith("P:"):
            prefix, val = person(slot[2:])
            text += prefix
            typ = "PERSON"
        elif slot == "E":
            val, typ = email(), "EMAIL"
        elif slot == "I":
            val, typ = iban(R.choice(["DE", "DE", "AT", "CH"])), "IBAN"
        else:
            val, typ = secret(), "SECRET"
        ents.append({"start": len(text), "end": len(text) + len(val), "type": typ, "value": val})
        text += val
        i = m.end()
    text += tpl[i:]
    return {"text": text, "entities": ents, "tags": tags}


T_HELDOUT_PERSON = [
    ("Gestern hat {P:full} das Notebook abgeholt.", "full"),
    ("Termin mit {P:title_last} am Donnerstag um 10 Uhr.", "title_last"),
    ("Ansprechpartnerin ist {P:title_full}.", "title_full"),
    ("{P:first} sagt, das WLAN im Besprechungsraum fällt ständig aus.", "first"),
    ("Kollege {P:full} braucht Admin-Rechte für das Testsystem.", "full"),
    ("hey, kannst du {P:lower} freischalten?", "lower"),
    ("Freigabe durch {P:full}, Vertretung {P:full}.", "full"),
    ("Danke {P:first}!", "first"),
]
T_HELDOUT_OTHER = ["Bitte setze {E} auf die Verteilerliste.", "Erstattung bitte an {I}, danke.",
                   "Kontoverbindung: {I} – Verwendungszweck Reisekosten", "Token: {S}",
                   "{P:full} <{E}> hat die IBAN {I} hinterlegt."]
NEGATIVE_HELDOUT = ["Der Kunde aus Stuttgart hat das Paket nicht erhalten.", "Bitte das Ticket an das Team Netzwerk geben.",
                    "Morgen ist Wartung am Exchange-Server.", "Die Volkswagen AG nutzt eine andere Lösung.",
                    "Am Hauptbahnhof Leipzig fällt der Aufzug aus.", "Sehr geehrte Damen und Herren, das System ist wieder online.",
                    "Weiß jemand, ob Teams heute stört?", "Die Lizenz für Adobe Acrobat läuft im Mai aus."]


def main_heldout():
    global R
    R = random.Random(4711)
    rows = []
    for tpl, kind in T_HELDOUT_PERSON:
        for _ in range(5):
            rows.append(fill(tpl, ["person", kind]))
    for tpl in T_HELDOUT_OTHER:
        for _ in range(5):
            rows.append(fill(tpl, ["other"]))
    for n in NEGATIVE_HELDOUT:
        rows.append({"text": n, "entities": [], "tags": ["negative"]})
    return rows


def write(rows, name):
    out = pathlib.Path(__file__).with_name(name)
    with out.open("w", encoding="utf-8") as f:
        for i, r in enumerate(rows):
            f.write(json.dumps({"id": f"{'ho' if 'heldout' in name else 'de'}-{i:03d}", **r}, ensure_ascii=False) + "\n")
    print(f"{len(rows)} sentences, {sum(len(r['entities']) for r in rows)} entities -> {out}")


def _gazetteer():
    data = pathlib.Path(__file__).resolve().parents[2] / "gateway" / "aism_gateway" / "data"
    def load(name):
        return {ln.strip().casefold() for ln in (data / name).read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")}
    return load("de_given_names.txt"), load("de_surnames.txt")


def _person_lists(rng, first, last, kind):
    f, l = rng.choice(first), rng.choice(last)
    titles = ["Herr", "Frau", "Herr Dr.", "Frau Dr.", "Prof."]
    return {"full": ("", f"{f} {l}"), "title_last": (rng.choice(titles) + " ", l), "first": ("", f),
            "title_full": (rng.choice(titles) + " ", f"{f} {l}"), "lower": ("", f"{f} {l}".lower())}[kind]


def _is_oov(value, kind, given, surnames):
    toks = value.split()
    if kind == "first":
        return toks[0].casefold() not in given
    if kind == "title_last":
        return toks[-1].casefold() not in surnames
    return toks[0].casefold() not in given or toks[-1].casefold() not in surnames


def fill_ext(rng, tpl, tags, first, last, given, surnames):
    """Like fill(), but with an explicit RNG/name pool and an oov flag on person entities."""
    text, ents, i = "", [], 0
    import re
    for m in re.finditer(r"\{(P:\w+|E|I|S)\}", tpl):
        text += tpl[i:m.start()]
        slot = m.group(1)
        if slot.startswith("P:"):
            kind = slot[2:]
            prefix, val = _person_lists(rng, first, last, kind)
            text += prefix
            typ = "PERSON"
            extra = {"oov": _is_oov(val, kind, given, surnames)}
        elif slot == "E":
            val, typ, extra = email(), "EMAIL", {}
        elif slot == "I":
            val, typ, extra = iban(rng.choice(["DE", "DE", "AT", "CH"])), "IBAN", {}
        else:
            val, typ, extra = secret(), "SECRET", {}
        ents.append({"start": len(text), "end": len(text) + len(val), "type": typ, "value": val, **extra})
        text += val
        i = m.end()
    text += tpl[i:]
    return {"text": text, "entities": ents, "tags": tags}


# Extension of the dev set (seed 20261006). Used to develop gazetteer/context rules.
# In-vocabulary names are on the built-in lists; the OOV names were checked against those lists
# on 2026-10-06 and are not. The original held-out file was not consulted.
_DEV_INV_FIRST = ["Anna", "Lukas", "Sophie", "Michael", "Thomas", "Frank", "Erika", "Max", "Laura", "Mehmet", "Jürgen", "Katharina"]
_DEV_OOV_FIRST = ["Nkechi", "Ines", "Sabine", "Ülkü", "Ayşe", "Svetlana", "Chinedu"]
_DEV_INV_LAST = ["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Becker", "Hoffmann", "Krüger"]
_DEV_OOV_LAST = ["Holtkamp", "Bierstedt", "Kaltenegger", "Ngono", "Mustermann", "Yılmaz", "Çelik"]
T_EXT_PERSON = [
    ("mein name ist {P:lower}.", "lower"),
    ("Ich heiße {P:full}.", "full"),
    ("Mit freundlichen Grüßen\n{P:full}\nBuchhaltung", "full"),
    ("Hallo {P:first}, der Job ist durch.", "first"),
    ("Danke, {P:first}!", "first"),
    ("{P:first} sagt, das Deployment war erfolgreich.", "first"),
    ("Liebe {P:first}, anbei das Protokoll.", "first"),
    ("Sehr geehrte {P:title_last}, wir bestätigen den Eingang.", "title_last"),
    ("Absender: {P:full}", "full"),
    ("Unterschrift: {P:full}", "full"),
    ("i. A. {P:full}", "full"),
    ("kannst du {P:lower} bescheid geben", "lower"),
    ("Für {P:title_full} liegt eine Nachricht im Postfach.", "title_full"),
    ("Der Account {P:lower} wurde heute gesperrt.", "lower"),
]
NEG_EXT = [
    "Hallo zusammen, das Meeting beginnt pünktlich.",
    "Danke für die schnelle Hilfe beim Deployment.",
    "Liebe Kolleginnen und Kollegen, kurze Info.",
    "Mein Name ist im Telefonbuch der Abteilung.",
    "Viele Grüße\nIT-Service\nStandort Berlin",
    "Wer sagt, dass der Build grün ist?",
    "Bitte Max. 3 Kopien anfertigen.",
    "Wir haben frank und frei über den Zeitplan diskutiert.",
    "Projekt Phoenix startet im Mai.",
    "Die Firma Müller GmbH liefert das Rack morgen.",
    "Schick das Protokoll an das Team, nicht an eine Person.",
    "Leite die Meldung an die Rufbereitschaft weiter.",
    "Meine Adresse steht im Intranet unter Kontakte.",
    "Office und Teams sind heute langsam.",
    "Der Wolf im Logo ist nur eine Zeichnung.",
]

# Fresh held-out set. Other seed, other templates, and an OOV name list disjoint from the dev
# extension. Do not add detector rules from misses on this file.
_H2_INV_FIRST = ["Paul", "Jonas", "Marie", "Felix", "Hannah", "Moritz", "Lena", "Emma", "Björn", "Giulia", "Dimitrios", "Wolfgang"]
_H2_OOV_FIRST = ["Ostap", "Brankica", "Yaren", "Ilaria", "Gül"]
_H2_INV_LAST = ["Meyer", "Wagner", "Schulz", "Koch", "Richter", "Klein", "Wolf", "Neumann", "Braun", "Lehmann"]
_H2_OOV_LAST = ["Vosskamp", "Reitmeier", "Diallo", "Bergström", "Iwanow", "Haddad", "Popescu", "Abiola", "Vuković", "Sørensen"]
T_H2_PERSON = [
    ("Könntest du {P:full} heute noch erreichen?", "full"),
    ("i. V. {P:full}", "full"),
    ("Gezeichnet: {P:full}", "full"),
    ("Ich bin {P:lower} und rufe wegen des Ausfalls an.", "lower"),
    ("Beste Grüße\n{P:full}\nEmpfang", "full"),
    ("Hi {P:first}, kurzer Hinweis zum Change.", "first"),
    ("Lieber {P:first}, die Freigabe liegt bei dir.", "first"),
    ("{P:first} meldet, dass das VPN wieder steht.", "first"),
    ("Vielen Dank {P:first}.", "first"),
    ("Für Rückfragen steht {P:title_last} bereit.", "title_last"),
    ("{P:first} und {P:first} teilen sich das Postfach.", "first"),
    ("Der Nutzeraccount von {P:lower} ist gesperrt.", "lower"),
    ("Ansprechpartner: {P:title_full}", "title_full"),
    ("Bitte {P:lower} nicht auf den Verteiler setzen.", "lower"),
]
T_H2_OTHER = [
    "Die neue Adresse lautet {E}.",
    "Rücküberweisung auf {I} veranlassen.",
    "IBAN {I} ist hinterlegt.",
    "Der Schlüssel {S} stand in der Konsole.",
    "{P:full} erreicht man unter {E}, Konto {I}.",
]
NEG_H2 = [
    "Die maximale Wartezeit beträgt fünf Minuten.",
    "Frank und frei bleibt die Diskussion im Forum.",
    "Bitte die Müller GmbH nicht mit dem Lager verwechseln.",
    "Kostenstelle Lange gehört zum Bereich Finanzen.",
    "Der Drucker im Flur heißt nicht Wolf.",
    "Teams und Outlook waren heute Morgen langsam.",
    "Wer übernimmt die Bereitschaft nächste Woche?",
    "Schick mir das Protokoll bis Donnerstag.",
    "Leite das an das Funktionspostfach weiter.",
    "Meine Adresse findet sich auf der Visitenkarte im Wiki.",
    "Sehr geehrte Damen und Herren, der Dienst ist wieder da.",
    "Hallo zusammen vom Standort Dresden.",
    "Danke für die Übersicht, das reicht.",
    "Mein Name ist in der Signatur der Mailingliste nicht enthalten.",
    "Viele Grüße\nService-Desk\nIntern",
    "Projekt Phoenix hat keinen Personenbezug.",
    "Die Referenz AT00 0000 0000 ist ein Platzhalter.",
    "Qwen und Docker bleiben auf dem Build-Rechner.",
]


def _rows_from(rng, person_templates, other_templates, negatives, first, last, given, surnames, repeats):
    rows = []
    pool_f = list(first)
    pool_l = list(last)
    for tpl, kind in person_templates:
        for _ in range(repeats):
            # alternate in-vocabulary and out-of-vocabulary pools by consuming the rng inside fill
            rows.append(fill_ext(rng, tpl, ["person", kind, "ext"], pool_f, pool_l, given, surnames))
    for tpl in other_templates:
        for _ in range(repeats):
            rows.append(fill_ext(rng, tpl, ["other", "ext"], pool_f, pool_l, given, surnames))
    for n in negatives:
        rows.append({"text": n, "entities": [], "tags": ["negative", "ext"]})
    return rows


def _split_pools(inv_f, oov_f, inv_l, oov_l):
    """Repeat the shorter side so a uniform draw is about half in-vocabulary and half not."""
    def balanced(inv, oov):
        inv, oov = list(inv), list(oov)
        if not oov:
            return inv
        times = max(1, round(len(inv) / len(oov)))
        return inv + oov * times
    return balanced(inv_f, oov_f), balanced(inv_l, oov_l)


def extend_dev(given, surnames):
    rng = random.Random(20261006)
    first, last = _split_pools(_DEV_INV_FIRST, _DEV_OOV_FIRST, _DEV_INV_LAST, _DEV_OOV_LAST)
    return _rows_from(rng, T_EXT_PERSON, [], NEG_EXT, first, last, given, surnames, 4)


def heldout_v2(given, surnames):
    rng = random.Random(424242)
    first, last = _split_pools(_H2_INV_FIRST, _H2_OOV_FIRST, _H2_INV_LAST, _H2_OOV_LAST)
    return _rows_from(rng, T_H2_PERSON, T_H2_OTHER, NEG_H2, first, last, given, surnames, 4)


def _write_ids(rows, name, prefix):
    out = pathlib.Path(__file__).with_name(name)
    with out.open("w", encoding="utf-8") as f:
        for i, r in enumerate(rows):
            f.write(json.dumps({"id": f"{prefix}-{i:03d}", **r}, ensure_ascii=False) + "\n")
    n_ent = sum(len(r["entities"]) for r in rows)
    n_oov = sum(1 for r in rows for g in r["entities"] if g.get("oov"))
    print(f"{len(rows)} sentences, {n_ent} entities ({n_oov} oov) -> {out}")


# Held-out v3. Frozen before the cascade triggers were tuned (seed 20261007).
# Names are disjoint from the dev pools and from held-out v1/v2. In-list names were checked
# against the built-in gazetteer; OOV names are not on those lists. Synthetic combinations only.
_V3_FORBIDDEN = {
    "anna", "lukas", "sophie", "jonas", "marie", "felix", "laura", "paul", "lea", "tim", "hannah",
    "moritz", "katharina", "jan-hendrik", "ülkü", "mehmet", "svetlana", "giulia", "björn", "ines",
    "frank", "peter", "sabine", "jürgen", "ayşe", "dimitrios", "karl-heinz", "lena", "max", "emma",
    "michael", "thomas", "erika", "nkechi", "chinedu", "ostap", "brankica", "yaren", "ilaria", "gül",
    "wolfgang", "müller", "schmidt", "schneider", "fischer", "weber", "meyer", "wagner", "becker",
    "schulz", "hoffmann", "koch", "richter", "klein", "wolf", "schröder", "neumann", "schwarz",
    "zimmermann", "braun", "krüger", "hartmann", "lange", "werner", "krause", "lehmann", "yılmaz",
    "kowalski", "nguyen", "großmann", "öztürk", "holtkamp", "bierstedt", "kaltenegger", "ngono",
    "mustermann", "çelik", "vosskamp", "reitmeier", "diallo", "bergström", "iwanow", "haddad",
    "popescu", "abiola", "vuković", "sørensen",
}
_V3_INV_FIRST = ["Stefan", "Klaus", "Andreas", "Birgit", "Uwe", "Heike", "Markus", "Torsten", "Brigitte", "Horst", "Dieter", "Helga"]
_V3_OOV_FIRST = ["Tijana", "Kwame", "Naledi", "Oksana", "Koffi", "Enisa", "Chioma", "Arben"]
_V3_INV_LAST = ["Schäfer", "Bauer", "Keller", "Berger", "Huber", "König", "Fuchs", "Vogel", "Sommer", "Stein", "Franke", "Krämer"]
_V3_OOV_LAST = ["Quirnbach", "Linscheid", "Okonkwo", "Schenkendorf", "Hölzken", "Białek", "Nordholt", "Piepenbrock", "Kaltwasser", "Seidensticker", "Eichwald"]
T_V3_PERSON = [
    ("Im Übergabeprotokoll hat {P:full} den Change quittiert.", "full"),
    ("Rückmeldung von {P:title_last} zur geplanten Wartung.", "title_last"),
    ("gez. {P:full}", "full"),
    ("Mit kollegialen Grüßen\n{P:full}\nSekretariat", "full"),
    ("Ich melde mich als {P:lower}.", "lower"),
    ("Die Ansprechpartnerin hierfür ist {P:title_full}.", "title_full"),
    ("Ob {P:first} das Zertifikat erneuern kann, ist offen.", "first"),
    ("{P:lower} steht unter dem Formular.", "lower"),
    ("Notiz an {P:full}: bitte das Rack prüfen.", "full"),
    ("Sowohl {P:first} als auch {P:first} haben Zugriff.", "first"),
    ("i. V. der Abteilungsleitung {P:full}", "full"),
    ("{P:title_full} wartet seit zehn Minuten in der Leitung.", "title_full"),
    ("Im Verzeichnis steht nur {P:lower}.", "lower"),
    ("Kurzer Gruß von {P:full} aus dem Lager.", "full"),
]
T_V3_OTHER = [
    "Neue Mailadresse: {E}.",
    "Bitte den Betrag auf {I} buchen.",
    "Verwendungszweck Reise, IBAN {I}.",
    "Der gefundene Schlüssel war {S}.",
    "Kontakt {P:full}, {E}, Konto {I}.",
]
NEG_V3 = [
    "Das Lager bleibt am Brückentag geschlossen.",
    "Bitte die Stückliste bis Freitag fortschreiben.",
    "Frank und frei ist hier nur eine Redewendung.",
    "Die Müller GmbH liefert das Gehäuse.",
    "Qwen läuft weiter auf dem Laborrechner.",
    "Kubernetes und Grafana bleiben unangetastet.",
    "Sehr geehrte Damen und Herren, der Wartungsvertrag läuft.",
    "Hallo zusammen, der Call entfällt.",
    "Danke für die Tabelle, mehr braucht es nicht.",
    "Mein Name steht nicht in dieser Meldung.",
    "Viele Grüße\nEmpfang\nHaus 2",
    "Die Kostenstelle wechselt zum Quartalsende.",
    "Max. vier Versuche, danach sperrt das Formular.",
    "Der Drucker im Kopierraum hat kein Papier.",
    "Projekt Phoenix hat einen neuen Meilenstein.",
    "Bitte das Funktionspostfach statt einer Person nutzen.",
    "Outlook und Teams waren kurz nicht erreichbar.",
    "Die Referenz CH00 0000 0000 ist ungültig.",
]


def _mail_local(rng, first, last):
    f, l = rng.choice(first), rng.choice(last)
    tr = str.maketrans({"ü": "ue", "ö": "oe", "ä": "ae", "ß": "ss", "ı": "i", "ş": "s", "Ü": "Ue", "Ö": "Oe",
                        "ł": "l", "Ł": "L", "ć": "c", "č": "c", "š": "s", "ž": "z"})
    local = rng.choice([f"{f}.{l}", f"{f[0]}.{l}", f"{l}{rng.randint(1, 99)}", f"{f}_{l}"]).translate(tr).lower()
    return f"{local}@{rng.choice(DOMAINS)}"


def _iban_rng(rng, country="DE"):
    lens = {"DE": 18, "AT": 16, "CH": 17}
    bban = "".join(rng.choice(string.digits) for _ in range(lens[country]))
    num = int("".join(str(int(c, 36)) for c in bban + country + "00"))
    s = f"{country}{98 - num % 97:02d}{bban}"
    spaced = rng.random() < 0.5
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4)) if spaced else s


def _secret_rng(rng):
    k = rng.choice(["sk", "akia", "ghp"])
    if k == "sk":
        return "sk-" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(32))
    if k == "akia":
        return "AKIA" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


def _fill_v3(rng, tpl, tags, first, last, given, surnames):
    text, ents, i = "", [], 0
    import re
    for m in re.finditer(r"\{(P:\w+|E|I|S)\}", tpl):
        text += tpl[i:m.start()]
        slot = m.group(1)
        extra = {}
        if slot.startswith("P:"):
            kind = slot[2:]
            prefix, val = _person_lists(rng, first, last, kind)
            text += prefix
            typ = "PERSON"
            extra = {"oov": _is_oov(val, kind, given, surnames)}
        elif slot == "E":
            val, typ = _mail_local(rng, first, last), "EMAIL"
        elif slot == "I":
            val, typ = _iban_rng(rng, rng.choice(["DE", "DE", "AT", "CH"])), "IBAN"
        else:
            val, typ = _secret_rng(rng), "SECRET"
        ents.append({"start": len(text), "end": len(text) + len(val), "type": typ, "value": val, **extra})
        text += val
        i = m.end()
    text += tpl[i:]
    return {"text": text, "entities": ents, "tags": tags}


def heldout_v3(given, surnames):
    pools = (
        (_V3_INV_FIRST, False, given), (_V3_OOV_FIRST, True, given),
        (_V3_INV_LAST, False, surnames), (_V3_OOV_LAST, True, surnames),
    )
    for pool, oov, bag in pools:
        for name in pool:
            folded = name.casefold()
            if folded in _V3_FORBIDDEN:
                raise SystemExit(f"v3 name {name} overlaps an older set")
            if oov and (folded in given or folded in surnames):
                raise SystemExit(f"v3 OOV name {name} is on the gazetteer")
            if not oov and folded not in bag:
                raise SystemExit(f"v3 in-list name {name} is not on the gazetteer")
    rng = random.Random(20261007)
    first, last = _split_pools(_V3_INV_FIRST, _V3_OOV_FIRST, _V3_INV_LAST, _V3_OOV_LAST)
    rows = []
    for tpl, kind in T_V3_PERSON:
        for _ in range(4):
            rows.append(_fill_v3(rng, tpl, ["person", kind, "v3"], first, last, given, surnames))
    for tpl in T_V3_OTHER:
        for _ in range(4):
            rows.append(_fill_v3(rng, tpl, ["other", "v3"], first, last, given, surnames))
    for n in NEG_V3:
        rows.append({"text": n, "entities": [], "tags": ["negative", "v3"]})
    persons = [g for r in rows for g in r["entities"] if g["type"] == "PERSON"]
    if not any(g.get("oov") for g in persons) or not any(not g.get("oov") for g in persons):
        raise SystemExit("v3 must mix in-list and OOV person names")
    return rows


def main():
    rows = []
    for tpl, kind in T_PERSON:
        for _ in range(5):
            rows.append(fill(tpl, ["person", kind]))
    for tpl in T_EMAIL:
        for _ in range(5):
            rows.append(fill(tpl, ["email"]))
    for tpl in T_IBAN:
        for _ in range(5):
            rows.append(fill(tpl, ["iban"] + (["iban_followed_by_caps"] if "BIC" in tpl else [])))
    for tpl in T_SECRET:
        for _ in range(5):
            rows.append(fill(tpl, ["secret"]))
    for tpl in T_MIXED:
        for _ in range(5):
            rows.append(fill(tpl, ["mixed"]))
    for n in NEGATIVE:
        rows.append({"text": n, "entities": [], "tags": ["negative"]})
    for _ in range(5):
        rows.append({"text": f"Die Nummer {bad_iban()} hat eine falsche Prüfziffer.", "entities": [], "tags": ["negative", "bad_iban"]})
    write(rows, "pii_eval_de.jsonl")
    # held-out set: other seed and templates, written after the detectors were tuned on the dev set
    write(main_heldout(), "pii_eval_de_heldout.jsonl")
    given, surnames = _gazetteer()
    ext = extend_dev(given, surnames)
    dev_path = pathlib.Path(__file__).with_name("pii_eval_de.jsonl")
    with dev_path.open("a", encoding="utf-8") as f:
        for i, r in enumerate(ext):
            f.write(json.dumps({"id": f"dx-{i:03d}", **r}, ensure_ascii=False) + "\n")
    print(f"appended {len(ext)} dev-extension sentences -> {dev_path}")
    _write_ids(heldout_v2(given, surnames), "pii_eval_de_heldout_v2.jsonl", "h2")
    _write_ids(heldout_v3(given, surnames), "pii_eval_de_heldout_v3.jsonl", "h3")


if __name__ == "__main__":
    main()
