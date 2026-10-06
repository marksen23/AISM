# AISM-Konformitätssuite

Ausführbare pytest-Suite zu [`../AISM-Konformitaet.md`](../AISM-Konformitaet.md). Version 0.2.0.

> **Status (05.10.2026):** 31 Tests. Am 05.10.2026 lokal gegen den Gateway-Prototyp ([`../../gateway/`](../../gateway/)) und den Orchestrator-Stub ([`../../orchestrator/`](../../orchestrator/)) ausgeführt, ohne Docker (siehe „Lokaler Lauf ohne Docker“). Ergebnis: K1 und K2 erreicht, K3 nicht (Details: [`../AISM-Konformitaet.md`](../AISM-Konformitaet.md) §7). Ein Lauf im Docker-Konformitäts-Stack steht noch aus.

## Installation

```bash
cd conformance/tests
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Testarten

| Marker | Bedeutung | Voraussetzung |
|---|---|---|
| `static` | prüft `docker-compose.yml` und die Policy-Datei | keine |
| `live` | HTTP-Tests gegen das Gateway | `AISM_BASE_URL`, Zugangsdaten |
| `capture` | beobachtet, was S2/S3 an S6, S4 und das Tool-Gateway senden | Capture-Mock (`AISM_MOCK_URL`) |
| `audit` | prüft das Audit-Log | Lesezugriff (`AISM_AUDIT_LOG`) |

Fehlende Voraussetzungen führen zu `skipped`, nicht zu `failed`. Übersprungene MUSS-Tests verhindern jedoch das Erreichen der jeweiligen Konformitätsstufe.

## Konfiguration

| Variable | Option | Standard | Bedeutung |
|---|---|---|---|
| `AISM_BASE_URL` | `--aism-base-url` | `http://127.0.0.1:8000` | Gateway (S2) |
| `AISM_API_KEY` | `--aism-api-key` | – | Client-Schlüssel (Bearer) |
| `AISM_USER_JWT` | `--aism-user-jwt` | – | Benutzer-JWT, gesendet im Header `AISM_USER_JWT_HEADER` (Standard `X-OpenWebUI-User-Jwt`) |
| `AISM_MODEL` | `--aism-model` | erstes Modell aus `/v1/models` | Modell-ID |
| `AISM_MOCK_URL` | `--aism-mock-url` | – | Capture-Mock, z. B. `http://127.0.0.1:18080` |
| `AISM_DIRECT_URLS` | – | siehe `conftest.py` | URLs, die **nicht** erreichbar sein dürfen (Bypass-Test) |
| `AISM_COMPOSE_FILE` | – | `../../docker-compose.yml` | für statische Tests |
| `AISM_POLICY_FILE` | – | `../../policy/policy.yaml`, sonst `policy.example.yaml` | für statische Tests |
| `AISM_AUDIT_LOG` | – | – | Pfad zur Audit-JSONL-Datei |
| `AISM_TIMEOUT` | – | `30` | HTTP-Timeout (s) |
| `AISM_REPORT` | – | `aism-report.json` | Berichtsdatei; Badges daneben |
| `AISM_ALLOWED_SIGNERS` | – | – | `allowed_signers`-Datei; AISM-K3-01 prüft damit eine Einzelsignatur (`.sig`) |
| `AISM_KEYRING` | – | – | `keyring.yaml`; AISM-K3-01 prüft ein Bündel (`.sigs`), AISM-K3-12 rotiert den Ring |
| `AISM_SIGNING_KEYS` | – | – | Manifest `Identität<TAB>relativer Pfad` der Test-Privatschlüssel für AISM-K3-12 |
| `AISM_POLICY_FAULT_INJECTION` | – | aus | `1`: AISM-K3-08 ersetzt die gemountete Policy-Datei kurz durch unsignierte/manipulierte Fassungen und stellt sie wieder her |
| `AISM_POLICY_RELOAD_WAIT` | – | `15` | Wartezeit (s) auf das Neuladen der Policy (K3-08) |
| `AISM_OIDC_TOKEN` / `AISM_OIDC_NEGATIVE_TOKENS` | – | – | gültiges IdP-Token bzw. kommagetrennte Tokens, die abgelehnt werden müssen (AISM-K2-21) |
| `AISM_IDP_URL` | – | – | Test-IdP; `run_in_docker.sh` holt damit die OIDC-Tokens |
| `AISM_LOCAL_DOWN`, `AISM_CLOUD_MOCK_URL` | – | – | nur Szenario Cloud-Fallback (AISM-K3-10) |
| `AISM_AUDIT_S3_ENDPOINT` | – | – | WORM-Senke, im Stack `http://audit-worm:8333` (AISM-K3-13, -14, -15) |
| `AISM_AUDIT_S3_BUCKET` / `AISM_AUDIT_S3_PREFIX` | – | – | Bucket `aism-audit`, Präfix `aism/` |
| `AISM_AUDIT_S3_ACCESS_KEY` / `AISM_AUDIT_S3_SECRET_KEY` | – | – | Laufzeit-Zugangsdaten; `prepare_audit_sink.sh` schreibt daraus `run/seaweed/s3.json` |
| `AISM_AUDIT_SIGNER` | – | – | Identität mit Rolle `audit`, Test: `aism-audit@localhost` |
| `AISM_KEYRING_STATE` | – | – | `keyring-state.json` neben dem Audit-Log |

## Ausführung

**Nur statische Prüfungen** (ohne laufenden Stack):

```bash
python3 -m pytest -m static
```

**Vollständiger Lauf im Docker-Konformitäts-Stack** (so am 05.10.2026 ausgeführt, Ergebnis K3; [`../AISM-Konformitaet.md`](../AISM-Konformitaet.md) §7):

```bash
# im Repository-Root
# 1. Laufzeit-Secrets in .env (nicht ins Repository!): AISM_UI_CLIENT_KEY, AISM_FORWARD_JWT_SECRET,
#    AISM_INTERNAL_TOKEN, AISM_QDRANT_API_KEY, AISM_N8N_WEBHOOK_TOKEN, AISM_SEARXNG_SECRET, z. B.:
for v in AISM_UI_CLIENT_KEY AISM_FORWARD_JWT_SECRET AISM_INTERNAL_TOKEN AISM_QDRANT_API_KEY AISM_N8N_WEBHOOK_TOKEN AISM_SEARXNG_SECRET; do
  echo "$v=$(openssl rand -hex 32)"; done > .env && chmod 600 .env
# 2. Test-Policy mit zwei Policy-Schlüsseln und einem Audit-Schlüssel signieren -> run/{policy,trust,keys}
sh conformance/tests/prepare_signed_policy.sh
# 3. S3-Zugangsdaten (nicht committen) und SeaweedFS-Identität
#    AISM_AUDIT_S3_ACCESS_KEY und AISM_AUDIT_S3_SECRET_KEY in .env, dann:
sh conformance/tests/prepare_audit_sink.sh
# 4. Stack starten (Capture-Mock statt S6/S4/n8n/SearXNG, Test-IdP, SeaweedFS als audit-worm)
C="docker compose -f docker-compose.yml -f conformance/tests/compose.conformance.yml"
$C up -d --build governance-proxy orchestrator aism-mock mock-idp audit-worm
# 5. Suite aus dem Client-Netz (Runner-Container nur in aism_frontend; erzeugt Test-JWT und OIDC-Tokens)
$C --profile runner run --rm -e AISM_REPORT=/repo/conformance/reports/aism-report.json aism-runner
```

Optional: `-f deploy/firewall/test/compose.ipv6.yml` für Dual-Stack-Netze (Firewall-Test mit IPv6).

**Szenario Cloud-Fallback (AISM-K3-04, -10)**, vor dem Standardlauf auf demselben Audit-Volume:

```bash
sh conformance/tests/prepare_cloud_scenario.sh        # signierte Cloud-Policy, Test-CA (CA-Schlüssel wird gelöscht)
CL="$C -f conformance/tests/compose.cloud-fallback.yml"
$CL up -d governance-proxy orchestrator aism-mock mock-cloud llama-mock mock-idp audit-worm
$CL stop llama-mock                                   # lokales Modell "ausgefallen"
$CL --profile runner run --rm aism-runner scenario_cloud_fallback.py test_k3_sovereign.py test_k2_governed.py -k "fallback or audit or egress"
$CL down                                              # ohne -v: Audit-Volume bleibt für den Standardlauf
```

Bekannte Stolperstellen auf dem Testhost: ohne systemd `dockerd` manuell starten; in einem Container-Host ohne Overlay-Unterstützung `--storage-driver vfs`; alte **iptables-legacy**-Regeln (`FORWARD`-Policy `DROP`) blockieren Bridge-Verkehr (siehe [`../../deploy/firewall/README.md`](../../deploy/firewall/README.md)).

Die Test-Schlüssel unter `run/` sind Wegwerfschlüssel; `run/` ist in `.gitignore` und gehört nicht ins Paket.

## CI

`.github/workflows/ci.yml` und `tools/ci-local.sh conformance` führen denselben Ablauf aus dem Repository-Root aus: `.env` anlegen oder ergänzen (inkl. `AISM_AUDIT_S3_*`); `prepare_audit_sink.sh`; `prepare_cloud_scenario.sh`; Cloud-Fallback-Szenario (lokales Modell gestoppt, Teilmenge `fallback or audit or egress`, Dienst `audit-worm` mit gestartet); `docker compose down` **ohne** `-v`; danach der vollständige Lauf, wieder mit `audit-worm`. Der vollständige Bericht muss Stufe K3 erreichen, mit `failed: 0` und `skipped: 0`. Berichte und Badges liegen unter `conformance/reports/ci/` (nicht versioniert) und werden als Artifact hochgeladen. `aism-runner` nutzt das lokal von `mock-idp` gebaute Image (`pull_policy: never`) und zieht `ghcr.io/marksen23/aism-test-tools:dev` nicht.

`TEST_USER_JWT` ist ein mit `AISM_FORWARD_JWT_SECRET` (HS256) signiertes Testtoken, dessen Claims auf die Rolle `it-ops` abgebildet werden (Test-Policy: Claim `groups` enthält `it-ops`). **Hinweis:** Open WebUI selbst überträgt keinen `groups`-Claim (nur `sub`, `email`, `name`, `role`); das Testtoken steht für eine Identität mit Gruppeninformation, z. B. aus OIDC. Beispiel:

```bash
python3 -c "import jwt,time,os; print(jwt.encode({'sub':'test-1','role':'user','groups':['it-ops'],'iss':'open-webui','iat':int(time.time()),'exp':int(time.time())+3600}, os.environ['AISM_FORWARD_JWT_SECRET'], algorithm='HS256'))"
```

Test-Policies in [`testdata/`](testdata/):

| Datei | Zweck |
|---|---|
| `policy.conformance.yaml` | Standardlauf: Mock-Modell `aism-mock-model`, `cloudEnabled: false`, `ticket_status_lookup` ohne Agent-Bindung |
| `policy.conformance-cloud.yaml` | Szenario für AISM-K3-04/-10: `cloudEnabled: true`, Cloud-Provider `https://mock-cloud:8443/v1` mit TLS (Test-CA). Die Stufe wird aus dem Standardlauf bestimmt. |

## Lokaler Lauf ohne Docker

So wurde der erste Lauf vom 05.10.2026 durchgeführt (Ergebnis K2, vor Signatur und Digests) (Linux, Python 3.13, venv mit `../../gateway/requirements.txt` und `requirements.txt`):

1. Mock im Split-Modus: API (S6/S4/Webhook-Ersatz) nur auf `127.0.0.1:18081`, Capture-Endpunkte auf `0.0.0.0:18080`:
   `python3 mock_upstream.py --host 127.0.0.1 --port 18081 --capture-host 0.0.0.0 --capture-port 18080`
2. Orchestrator-Stub auf `127.0.0.1:9000` (`INFERENCE_LOCAL_URL`, `EMBEDDINGS_URL`, `TOOL_GATEWAY_URL` → Mock-API, `GATEWAY_INTERNAL_URL=http://127.0.0.1:8001`, `POLICY_PATH` → Test-Policy).
3. Gateway: öffentlich `0.0.0.0:8000`, intern `127.0.0.1:8001` (`python -m aism_gateway`, `AUDIT_LOG_PATH` gesetzt).
4. Testsuite in einem eigenen Netz-Namespace (`ip netns`, veth-Paar 10.200.0.1/10.200.0.2) als Ersatz für das Client-Netz: von dort sind nur Gateway-Port 8000 und Capture-Port 18080 erreichbar; `AISM_DIRECT_URLS` listet Orchestrator, Mock-API und internen Gateway-Port.

Der Namespace bildet die Docker-Netztrennung nur nach; er ersetzt den Lauf im Konformitäts-Stack nicht.

Für AISM-K3-04 zusätzlich: zweiter Mock mit `--tls-cert/--tls-key` auf `127.0.0.1:18443`, Gateway mit `AISM_CA_BUNDLE=<Test-CA>` und `policy.conformance-cloud.yaml`; danach mindestens einen expliziten Cloud-Request (Modell `example-large-model`, ohne PII) senden und die Suite gegen das Audit-Log dieses Laufs ausführen.

## Capture-Mock

`mock_upstream.py` (nur Standardbibliothek) ersetzt die Upstreams des Orchestrators. Es zeichnet jede Anfrage auf (`GET /_captured`, `POST /_reset`) und steuert Szenarien über Marker in der Benutzernachricht:

| Marker | Verhalten |
|---|---|
| `AISM-TEST:ALLOWED_TOOL` | Tool-Call `ticket_status_lookup` mit gültigen Argumenten (Positivkontrolle) |
| `AISM-TEST:DISALLOWED_TOOL` | Tool-Call `delete_ticket` (nicht in der Allowlist) |
| `AISM-TEST:INVALID_ARGS` | Tool-Call `ticket_status_lookup` mit schemawidrigen Argumenten |
| `AISM-TEST:WEB_SEARCH` | Tool-Call `web_search` (AISM-K2-13, -19); `GET /search` liefert ein SearXNG-artiges JSON mit einer synthetischen E-Mail-Adresse |
| `AISM-TEST:WRITE_TOOL` | Tool-Call `ticket_add_comment` (schreibend, bestätigungspflichtig, AISM-K2-20) |
| `AISM-TEST:ECHO` | gibt den empfangenen (maskierten) Benutzertext zurück, im Stream in 3-Zeichen-Chunks (Platzhalter über Chunk-Grenzen, AISM-K2-18) |

Optionen: `--capture-port` trennt `/_captured`/`/_reset` von der API (Split-Modus); `--tls-cert`/`--tls-key` liefern die API per HTTPS aus (Mock-Cloud-Provider für AISM-K3-04).

Der Mock hat keine Authentifizierung und darf nur in Testumgebungen laufen.

## Bericht und Badge

Nach jedem Lauf entstehen:

- `aism-report.json`: Ergebnis je Test-ID, Auswertung je Stufe, erreichte Stufe (Format: [`../AISM-Konformitaet.md`](../AISM-Konformitaet.md) §6),
- `aism-report-badge.json`: Endpoint-JSON im Format von shields.io (`schemaVersion`, `label`, `message`, `color`),
- `aism-report-badge.svg`: lokal erzeugtes Badge.

## Selbsttest

Der Mock ist selbst ein OpenAI-kompatibler Server und kann als **absichtlich nicht konformes** „Gateway“ dienen, um die Testlogik zu prüfen:

```bash
python3 mock_upstream.py --port 18080 &
AISM_BASE_URL=http://127.0.0.1:18080 AISM_MOCK_URL=http://127.0.0.1:18080 python3 -m pytest -m live
```

Erwartet: Format-Tests (AISM-K1-01 bis -04, -07) bestehen. Governance-Tests schlagen fehl (keine Authentifizierung, keine Maskierung, kein Policy-Endpunkt, keine Tool-Behandlung). Einige Tests bestehen in diesem Aufbau trivial (K1-05, K2-06, K2-07, K3-02), weil der Mock gleichzeitig Gateway und Upstream ist; aussagekräftig sind sie nur im Konformitäts-Stack.
