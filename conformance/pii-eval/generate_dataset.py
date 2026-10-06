#!/usr/bin/env python3
"""Generates a small SYNTHETIC German PII evaluation set (deterministic, seed 20261005).

All names are random combinations of common German (and a few other) first and last names; e-mail
addresses use reserved domains (example.com/.org/.net, RFC 2606); IBANs are synthetic with a valid
mod-97 check digit; secrets are random strings in common key formats. No real persons or accounts.
Output: pii_eval_de.jsonl (dev set, used to find detector weaknesses) and pii_eval_de_heldout.jsonl
(held-out: other seed + templates, only used for measuring)
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


if __name__ == "__main__":
    main()
