# Programy

Każdy program serwera to jeden plik wykonywalny Go, konfigurowany zmiennymi środowiskowymi (w laboratorium: `deploy/lab/docker-compose.yml` i `.env`). Agenci są konfigurowani plikiem YAML i z panelu. Wszystkie programy serwera:

- logują w JSON na standardowe wyjście (`docker compose logs <usługa>`);
- wystawiają metryki Prometheus na `SIEM_METRICS_ADDR` (domyślnie `:9100`, tylko w sieci Dockera), a z `SIEM_PPROF=1` także profiler `/debug/pprof/`;
- łączą się z NATS pod `SIEM_NATS_URL` (domyślnie `nats://nats:4222`) i same zakładają potrzebne strumienie i konsumentów;
- kończą się czysto po SIGTERM: dokańczają bieżącą paczkę, nie potwierdzając niedokończonej.

Wersja programu pochodzi z gita (`git describe`, ustawiana przy budowaniu przez `deploy.sh`) i jest widoczna w logu startowym (`deploy.sh` wypisuje ją na końcu jako „gotowe: wersja …”).

Spis: [siem_agent](#siem_agent--agent-windows) · [siem-collector](#siem-collector--kolektor-syslog) · [siem-connector](#siem-connector--konektor-api) · [siem-ingest](#siem-ingest) · [siem-normalizer](#siem-normalizer) · [siem-writer](#siem-writer) · [siem-detector](#siem-detector) · [siem-archiver](#siem-archiver) · [siem-backup](#siem-backup) · [siem-api](#siem-api--panel-hliðskjálf) · [siem-loadgen](#siem-loadgen) · [narzędzia](#narzędzia)

---

## siem_agent – agent Windows

Kod: `agent/cmd/siem_agent`. Usługa Windows `SiemAgent`, instalowana w `C:\Program Files\Heimdall`, dane w `C:\ProgramData\Heimdall` (konfiguracja, certyfikaty, stan odczytu, bufor dyskowy, logi, dziennik ochrony).

**Co robi:** subskrybuje kanały dziennika zdarzeń (Security, System, Application, Sysmon, PowerShell, Defender, Harmonogram zadań – według profilu z panelu), renderuje XML, paczkuje i wysyła do `siem-ingest`. Pilnuje rozmiaru dzienników (`logwatch` – ostrzega, zanim Windows nadpisze nieodczytane zdarzenia), trzyma zdarzenia w buforze dyskowym przy braku łączności, ogranicza zużycie CPU, pamięci i łącza, co minutę wysyła heartbeat, chroni usługę przed zatrzymaniem.

**Polecenia** (`siem_agent help`):

| Polecenie | Działanie |
|---|---|
| `install [-server adres] [-token token] [-profile workstation\|server\|dc] [-start-at now\|oldest] [-no-start]` | instalacja usługi; z `-token` rejestracja w panelu (agent sam generuje klucz) |
| `status` | stan usługi, połączenia, kanałów, bufora, limitów i ochrony |
| `start`, `restart`, `stop [-token T]` | sterowanie usługą; zatrzymanie chronionego agenta wymaga tokenu z panelu |
| `test` | sprawdzenie połączenia z serwerem |
| `set-server <adres>` | zmiana adresu serwera (restart agenta) |
| `upgrade [-token T]` | aktualizacja programu z folderu nowej wersji |
| `uninstall [-token T] [-purge]` | odinstalowanie (`-purge` usuwa też dane i certyfikaty) |
| `check` | walidacja konfiguracji, certyfikatów i uprawnień |
| `run` | praca w konsoli zamiast usługi (diagnostyka) |
| `enroll -server <adres> -token <token> -dir <katalog>` | rejestracja bez instalacji usługi |
| `version` | wersja |

Opcja `-config <plik>` wskazuje inną konfigurację. Instalator MSI (`deploy/lab/msi`, budowany przez `deploy.sh agent`) wywołuje te same polecenia; deinstalacja chronionego agenta przez MSI wymaga `UNINSTALL_TOKEN=`.

**Konfiguracja lokalna** (`agent.yaml`, przykład: `agent/configs/agent.example.yaml`):

| Klucz | Znaczenie |
|---|---|
| `server.url`, `server.panel_url` | adres ingestu (`https://…:8443/v1/ingest`) i panelu (konfiguracja z grupy) |
| `server.ca_file`, `cert_file`, `key_file`, `timeout` | certyfikaty mTLS |
| `state_dir` | katalog stanu (zakładki odczytu, bufor) |
| `start_at` | `now` – tylko nowe zdarzenia, `oldest` – od początku dziennika |
| `batch.max_events`, `max_bytes`, `flush_interval`, `flush_max_wait`, `flush_min_events`, `max_event_bytes` | paczkowanie (mała paczka poniżej `flush_min_events` czeka do `flush_max_wait`, domyślnie 50 zdarzeń / 10 s) |
| `limits.priority`, `cpu_max_percent`, `memory_soft_mb`, `memory_hard_mb`, `max_eps`, `max_send_kbps`, `max_procs` | „kaganiec” zasobów |
| `buffer.max_mb`, `on_full` (`pause`\|`drop_oldest`), `min_free_mb` | bufor dyskowy (domyślnie 1 GB) |
| `logging.level`, `max_size_mb`, `max_files` | log agenta |
| `channels[].name`, `event_ids` | kanały i identyfikatory zdarzeń (gdy agent nie dostaje profilu z panelu) |

Panel nadpisuje kanały, limity i ochronę według grupy agenta (`/enroll/v1/config`, sprawdzane co kilka minut; `SIEM_CONFIG_POLL_SECONDS` skraca to w testach). Lokalny plik decyduje o serwerze, certyfikatach i katalogu stanu. Szczegóły instalacji, ochrony i diagnostyki: [README.md](../README.md#instalacja-agenta-na-komputerze).

## siem-collector – kolektor syslog

Kod: `agent/cmd/siem_collector`. Agent w trybie serwerowym (Linux albo Windows; w laboratorium kontener `collector`). Odbiera syslog (RFC 3164, RFC 5424, sam `<PRI>`) po UDP i TCP i wysyła wiadomości jak agent – mTLS, paczki, bufor dyskowy, heartbeat, odnawianie certyfikatu. Nie dekoduje: dekodowanie robi normalizator, więc zmiana dekodera nie wymaga zmian na kolektorze.

```
siem-collector enroll -server <adres> -token <token> -ca ca.crt -dir <katalog>
siem-collector run -config <katalog>/collector.yaml
siem-collector version
```

`collector.yaml`: wspólne klucze z konektorem (`server`, `state_dir`, `batch`, `buffer`, `max_eps`) oraz `syslog.udp`, `syslog.tcp` (adresy nasłuchu, np. `:514`), `syslog.max_message_kb`, `syslog.allow` (lista sieci CIDR, z których przyjmowane są wiadomości – syslog nie ma uwierzytelnienia, więc lista jest zalecana). Rejestracja w laboratorium: `deploy/lab/collector-enroll.sh [grupa]`.

## siem-connector – konektor API

Kod: `agent/cmd/siem_connector`. Agent pobierający logi z API chmury. Obecnie Entra ID przez Microsoft Graph: logowania (`signIns`, wymaga Entra ID P1/P2) i zmiany w katalogu (`directoryAudits`). Kursor odczytu jest w stanie konektora, okna zachodzą na siebie (logi Graph spływają z opóźnieniem), duplikaty usuwa serwer.

Polecenia jak w kolektorze (`enroll`, `run -config connector.yaml`, `version`). Klucze `entra`:

| Klucz | Znaczenie |
|---|---|
| `tenant_id`, `client_id`, `client_secret_file` | aplikacja w Entra ID (sekret w osobnym pliku) |
| `login_url`, `graph_url` | adresy API (w laboratorium symulator `entrasim`) |
| `sign_ins`, `audits` | które logi pobierać (domyślnie oba) |
| `interval` (1m), `overlap` (15m), `lookback` (24h) | rytm, zakładka, zasięg pierwszego startu |

Rejestracja w laboratorium: `deploy/lab/service-enroll.sh connector [grupa]` (tworzy też sekret wspólny z symulatorem).

## siem-ingest

Kod: `server/cmd/siem-ingest`, `server/internal/ingest`. Punkt wejścia dla agentów (port 8443, HTTPS z certyfikatem klienta).

| Endpoint | Działanie |
|---|---|
| `POST /v1/ingest` | paczka zdarzeń (gzip + JSON, kontrakt v1) → `SIEM_RAW`; 200 po potwierdzeniu przez NATS |
| `POST /v1/heartbeat` | heartbeat agenta → `SIEM_HEARTBEATS` |

Odmowy: 429 (za dużo równoległych żądań – `SIEM_INGEST_MAX_INFLIGHT`, heartbeaty osobno `SIEM_INGEST_MAX_HEARTBEATS`), 503 (kolejka zapełniona powyżej `SIEM_INGEST_QUEUE_HIGH_WATER` albo NATS niedostępny), 413 (paczka za duża, także po rozpakowaniu), 403 (`agent_id` w paczce niezgodny z certyfikatem). Certyfikat unieważniony w panelu jest odrzucany przy połączeniu. Odmowy 429 i 503 mają nagłówek `Retry-After`.

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_LISTEN` | `:8443` | adres nasłuchu |
| `SIEM_TLS_CERT`, `SIEM_TLS_KEY` | `/certs/server.*` | certyfikat serwera |
| `SIEM_TLS_CA`, `SIEM_TLS_AGENTS_CA` | `/certs/ca.crt`, `/certs/agents-ca.crt` | CA, którym ufa serwer (laboratoryjne i rejestracji tokenem) |
| `SIEM_INGEST_MAX_INFLIGHT` | 64 | równoległe paczki |
| `SIEM_INGEST_MAX_HEARTBEATS` | 128 | równoległe heartbeaty (masowy powrót agentów) |
| `SIEM_INGEST_QUEUE_HIGH_WATER` | 0.9 | zajętość kolejki, od której odpowiedź to 503 |
| `SIEM_QUEUE_RAW_MAX_MB`, `SIEM_QUEUE_EVENTS_MAX_MB`, `SIEM_QUEUE_MAX_AGE` | 8192, 8192, brak | limity strumieni (wspólne dla usług potoku) |

Metryki: `siem_ingest_events_total`, `siem_ingest_batches_total{result}`, `siem_ingest_request_seconds`, `siem_ingest_in_flight`, `siem_ingest_queue_fill_ratio`.

## siem-normalizer

Kod: `server/cmd/siem-normalizer`, `server/internal/normalize`, `internal/decode`. Konsument `normalizer` na `SIEM_RAW`.

- Zdarzenia Windows: parser XML (`EvtRender`), pola `EventData`/`UserData` do `fields`, pola wspólne (konto, domena, adres, proces, akcja, wynik) według identyfikatora zdarzenia, opis po polsku (`internal/windesc`).
- Syslog i API: dekodery (wbudowane w `internal/decode/builtin` i z panelu przez NATS KV `SIEM_DECODERS`). Opis: [dekodery.md](dekodery.md).
- Osoba (`user_identity`) według konfiguracji z NATS KV `SIEM_IDENTITY`.
- Kontrola czasu: czas spoza zakresu albo z przyszłości – `time_quality` = `invalid`/`future`, czas przyjęcia zamiast zdarzenia.
- Kwarantanna dla zdarzeń, których nie da się znormalizować.
- Ponowne przetwarzanie kwarantanny na prośbę panelu (temat `siem.reprocess`).

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_NORMALIZER_WORKERS` | liczba rdzeni | równoległe paczki |
| `SIEM_PIPELINE` | `live` | `replay` – kopia dla odtwarzania z archiwum (strumienie `SIEM_REPLAY_*`) |
| `SIEM_SYSLOG_TZ` | `Europe/Warsaw` | strefa dla nagłówków syslog bez strefy (ustawiana w compose) |

Metryki: `siem_normalizer_events_total`, `siem_normalizer_quarantined_total`, `siem_normalizer_batch_seconds`.

## siem-writer

Kod: `server/cmd/siem-writer`, `server/internal/chwriter`. Konsument `clickhouse-writer` na `SIEM_EVENTS`. Zbiera paczki i zapisuje je jednym INSERT-em do `siem.events` i `siem.quarantine`; potwierdza wiadomości po udanym zapisie.

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_CLICKHOUSE_ADDR`, `SIEM_CLICKHOUSE_USER`, `SIEM_CLICKHOUSE_PASSWORD` | `clickhouse:9000`, –, – | połączenie (konto `siem_writer`) |
| `SIEM_WRITER_MAX_ROWS` | 20000 | wiersze w jednym INSERT |
| `SIEM_WRITER_FLUSH` | 1s | maksymalny czas zbierania |
| `SIEM_PIPELINE` | `live` | `replay` – zapis do `siem.events_replay` |

Metryki: `siem_writer_rows_total`, `siem_writer_insert_seconds`, `siem_writer_pipeline_latency_seconds` (od przyjęcia przez ingest do zapisu).

## siem-detector

Kod: `server/cmd/siem-detector`, `server/internal/detector`, `internal/detect`, `internal/alerts`. Gjallarhorn: wszystkie mechanizmy detekcji ([architektura.md](architektura.md#detekcja-gjallarhorn), [reguly.md](reguly.md)). Działa w jednej kopii (blokada doradcza w Sadze). Stosuje migracje schematu `gjallarhorn`, synchronizuje listę reguł z panelem, usuwa stare alerty.

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_DETECTOR_DB_URL` | – | Saga (rola `siem_detector`) |
| `SIEM_RULES_DIR` | `/rules` | katalog reguł (lab: `/rules/current`, przełączany atomowo przez `deploy.sh rules`) |
| `SIEM_DETECTION_MODE` | `stream` | `stream`, `index_query` albo `both` (lab) – które silniki działają |
| `SIEM_DETECTOR_CH_ADDR`, `_USER`, `_PASSWORD` | `clickhouse:9000`, `siem_detector`, – | ClickHouse dla silnika zapytań, korelacji i ciszy źródła; bez hasła – tylko silnik w locie |
| `SIEM_INDEX_INTERVAL`, `SIEM_INDEX_DELAY` | 1m, 2m | rytm silnika zapytań i opóźnienie za bieżącym czasem (zapis w ClickHouse) |
| `SIEM_INDEX_LOOKBACK`, `SIEM_INDEX_OVERLAP` | 1h, 5m | zasięg pierwszego przebiegu i zakładka |
| `SIEM_INDEX_MAX_ROWS` | 100000 | zdarzeń w jednym przebiegu |
| `SIEM_SOURCE_SILENCE_MIN` | 1h | najkrótszy próg ciszy źródła |
| `SIEM_ALERT_RETENTION_DAYS` | 365 | usuwanie zamkniętych alertów (0 = nigdy) |

Metryki: `siem_detector_events_total`, `_matches_total`, `_alerts_total{result}`, `_errors_total{stage}`, `_rules`, `_rule_errors`, `_threshold_keys`, `_eval_seconds_total`, `_index_lag_seconds`, `_index_rows_total`, `_index_runs_total`, `_last_event_timestamp_seconds`.

## siem-archiver

Kod: `server/cmd/siem-archiver`, `server/internal/archiver`, `internal/urd`. Urd: archiwum NIS2 oryginalnych paczek. Konsument `archiver` na `SIEM_RAW` (zakładany tylko przy włączonej archiwizacji w polityce). Też: weryfikacja łańcucha, retencja, eksporty dla audytora, polecenia odtworzenia, wykonywanie zmian polityki z panelu (z opóźnieniem dla osłabień), uzgodnienie spisu z dyskiem po przywróceniu kopii bazy i decyzje administratora o plikach nieznanych spisowi (`urd.recoveries`, zapis w `archive/recoveries/`).

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_ARCHIVE_DB_URL` | – | Saga (rola `siem_archiver`) |
| `SIEM_ARCHIVE_DIR` | `/archive` | katalog archiwum (lab: montowany z `SIEM_ARCHIVE_PATH`) |
| `SIEM_ARCHIVE_SEGMENT_MB`, `SIEM_ARCHIVE_SEGMENT_AGE` | 64, 30s | zamknięcie segmentu |
| `SIEM_ARCHIVE_RETENTION_DAYS` | 30 | retencja domyślna (polityka w panelu) |
| `SIEM_ARCHIVE_MIN_RETENTION_DAYS`, `_MAX_RETENTION_DAYS` | 30, 3650 | granice retencji ustawianej w panelu |
| `SIEM_ARCHIVE_POLICY_GRACE` | 24h | opóźnienie osłabienia polityki |
| `SIEM_ARCHIVE_VERIFY_EVERY`, `_VERIFY_BUDGET_GB` | 6h, 50 | weryfikacja i ile GB czytać na przebieg |
| `SIEM_ARCHIVE_MIN_FREE_GB`, `_MIN_FREE_PERCENT`, `_WARN_FREE_PERCENT` | 2, 5, 15 | ochrona dysku: poniżej minimum archiwizacja wstrzymana (zdarzenia czekają w kolejce) |
| `SIEM_ARCHIVE_EXPORT_DIR`, `_EXPORT_TOOLS`, `_EXPORT_KEEP_DAYS` | `/exports`, `/export-tools`, 7 | eksporty i czytnik `odczytaj.exe` |
| `SIEM_ARCHIVE_EXCLUDE_AGENTS` | – | prefiksy agentów pomijanych (np. `agt-load-` – generator) |

Metryki: `siem_archive_*` (segmenty, bajty, weryfikacje, wolne miejsce).

## siem-backup

Kod: `server/cmd/siem-backup`, `server/internal/backup`, `internal/backupcfg`. Kopie zapasowe według ustawień z panelu ([operacje.md](operacje.md#kopie-zapasowe)). Kontener `backup` (obraz na bazie `postgres:18-alpine` z `pg_dump`, gpg, rclone i OpenSSH – `deploy/lab/backup/Dockerfile`) działa jako root, żeby czytać dane Grafany i hasło kopii; pliki kopii oddaje użytkownikowi stosu.

```
siem-backup serve     usługa (domyślnie)
siem-backup run       kopia teraz – zlecenie dla działającej usługi, czeka na wynik (./backup.sh)
```

Co 15 s usługa zapisuje swój stan w Sadze (`backup_runner`), wykonuje zlecenia z panelu (`backup_requests`: kopia, test połączenia, nowy klucz SSH) i kopie z harmonogramu, wszystko po kolei. Wyniki trafiają do `backup_runs`, a metryki dla alertów Grafany do `metrics/backup.prom`.

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_BACKUP_DB_URL` | – | Saga (rola `saga_admin` – `pg_dump` całej bazy) |
| `SIEM_BACKUP_TZ` | `Europe/Warsaw` | strefa harmonogramu |
| `SIEM_BACKUP_DIR`, `_STATE_DIR`, `_PASS_FILE` | `/backup`, `/state`, `/secrets/backup.pass` | kopie lokalne, stan (klucze), hasło kopii |
| `SIEM_BACKUP_STACK_DIR`, `_ARCHIVE_DIR`, `_GRAFANA_DIR`, `_METRICS_DIR` | `/stack`, `/archive`, `/grafana`, `/metrics` | źródła kopii i metryki |
| `SIEM_BACKUP_UID`, `_GID` | 1000 | właściciel plików kopii |
| `SIEM_BACKUP_SERVER_NAME` | nazwa kontenera | nazwa serwera w opisie kopii |
| `SIEM_BACKUP_REMOTE`, `_REMOTE_KEEP_DAYS` | – | dawne ustawienia z `.env`, przenoszone do panelu przy pierwszym starcie |

## siem-api – panel Hliðskjálf

Kod: `panel/cmd/siem-api`, `panel/internal/*`, frontend `panel/web`. Backend HTTPS (port 8444) z wbudowanym frontendem: API panelu (`/api/v1/…`, sesje w ciasteczku), rejestracja i konfiguracja agentów (`/enroll/v1/register|renew|config`), wysyłka powiadomień z outboxu, synchronizacja heartbeatów, konfiguracji dekoderów i tożsamości do NATS. Przekaźnik alertów Grafany na `SIEM_API_INTERNAL_LISTEN` (tylko sieć stosu). Moduły: [panel.md](panel.md).

```
siem-api                                   serwer (domyślnie)
siem-api bootstrap-admin -username admin   pierwsze konto administratora (wypisuje hasło startowe)
siem-api reset-password -username jan      nowe hasło startowe
```

W laboratorium: `docker compose run --rm api bootstrap-admin -username admin`.

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_API_DB_URL` | – | Saga (rola `siem_api`) |
| `SIEM_API_LISTEN`, `SIEM_TLS_CERT`, `SIEM_TLS_KEY` | `:8444`, `/certs/server.*` | HTTPS |
| `SIEM_CLICKHOUSE_ADDR`, `_USER`, `_PASSWORD` | `clickhouse:9000`, –, – | wyszukiwarka (konto `siem_panel`) |
| `SIEM_NATS_URL` | – | NATS (bez NATS panel działa, ale bez heartbeatów i dostarczania konfiguracji) |
| `SIEM_AGENTS_CA_CERT`, `SIEM_AGENTS_CA_KEY`, `SIEM_ROOT_CA` | `/certs/…` | CA agentów (wystawianie certyfikatów) i CA serwera (do paczek) |
| `SIEM_PUBLIC_SERVER` | – | adres serwera wpisywany do paczek instalacyjnych |
| `SIEM_AGENT_EXE` | `/agent-dist/siem_agent.exe` | program agenta do paczek |
| `SIEM_PROMETHEUS_URL` | – | strona Stan systemu |
| `SIEM_GRAFANA_URL` | adres serwera panelu, port 3000 | adres Grafany dla przeglądarki – linki do pulpitów i alertów w Himinbjörgu |
| `SIEM_ARCHIVE_EXPORT_DIR` | – | pobieranie eksportów archiwum |
| `SIEM_ALERT_NOTIFY_PER_RULE`, `SIEM_ALERT_NOTIFY_WINDOW` | 5, 10m | „burza alertów”: ponad limit w oknie – wiadomość zbiorcza |
| `SIEM_ANCHOR_HOUR`, `SIEM_ANCHOR_TZ` | 7, `Europe/Warsaw` | dzienna kotwica archiwum na kanał |
| `SIEM_API_INTERNAL_LISTEN`, `SIEM_ALERT_RELAY_TOKEN` | `:8081`, – | przekaźnik alertów Grafany na kanały panelu |
| `SIEM_SYSLOG_TZ` | `Europe/Warsaw` | test dekoderów w panelu |

## siem-loadgen

Kod: `server/cmd/siem-loadgen`, `server/internal/loadgen`. Generator ruchu: symuluje tysiące agentów z realistyczną mieszanką zdarzeń. Opis użycia, flag i procedury testu: [testy-obciazeniowe.md](testy-obciazeniowe.md).

## Narzędzia

| Program | Kod | Do czego |
|---|---|---|
| `siem-pki` | `tools/cmd/siem-pki` | certyfikaty laboratorium: `ca`, `server [-hosts]`, `agents-ca`, `agent [-id]`, `package -id … [-server]` (paczka instalacyjna z kluczem). Tylko laboratorium – docelowo agenci rejestrują się tokenem. |
| `siem-ingest-stub` | `tools/cmd/siem-ingest-stub` | testowy `/v1/ingest` zapisujący zdarzenia do pliku NDJSON (`-listen :8443 -out data/events.ndjson`); do testów agenta bez serwera |
| `fortisim` | `tools/cmd/fortisim` | symulator syslog FortiGate: `-target 192.168.88.98:514 -proto udp\|tcp -scenario traffic\|vpn-ok\|vpn-brute\|vpn-spray\|admin-brute\|utm\|mix -count N -every 100ms -user -attacker -header bare\|rfc3164\|rfc5424 -dry` |
| `entrasim` | `tools/cmd/entrasim`, `internal/entrasim` | symulator Microsoft Graph (kontener `entrasim`): tło logowań i scenariusze na żądanie – `curl -X POST 'http://127.0.0.1:8099/sim/scenario?name=spray'`; scenariusze `normal`, `spray`, `brute`, `success-after-failures`, `foreign`, `mfa-fatigue`, `admin-role` (parametry `user=`, `attacker=`) |
| `odczytaj` | `tools/cmd/odczytaj` | czytnik eksportu archiwum dla audytora (Windows, bez instalacji): sprawdza integralność paczki i zapisuje raport oraz zdarzenia dnia po polsku w podfolderze `ODCZYT` |

Budowanie: [rozwoj.md](rozwoj.md#budowanie).
