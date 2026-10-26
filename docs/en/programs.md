# Programs

Every server program is a single Go executable configured with environment variables (installation: `deploy/vardr/docker-compose.yml` and `.env`; lab: `deploy/lab/docker-compose.yml`). Agents are configured with a YAML file and from the panel. All server programs:

- log JSON to standard output (`docker compose logs <service>`), in English;
- expose Prometheus metrics on `SIEM_METRICS_ADDR` (default `:9100`, Docker network only), and with `SIEM_PPROF=1` also the `/debug/pprof/` profiler;
- connect to NATS at `SIEM_NATS_URL` (default `nats://nats:4222`) and create the streams and consumers they need;
- stop cleanly on SIGTERM: they finish the current batch without acknowledging an unfinished one.

The program version comes from git (`git describe`, set at build time) and is visible in the start log.

Index: [vardr-agent](#vardr-agent--windows-agent) · [siem-collector](#siem-collector--syslog-collector) · [siem-connector](#siem-connector--api-connector) · [siem-ingest](#siem-ingest) · [siem-normalizer](#siem-normalizer) · [siem-writer](#siem-writer) · [siem-detector](#siem-detector) · [siem-archiver](#siem-archiver) · [siem-backup](#siem-backup) · [siem-api](#siem-api--hliðskjálf-panel) · [siem-loadgen](#siem-loadgen) · [tools](#tools)

---

## vardr-agent – Windows agent

Code: `agent/cmd/vardr-agent`. The `SiemAgent` Windows service, installed in `C:\Program Files\SiemAgent`, data in `C:\ProgramData\SiemAgent` (configuration, certificates, read state, disk buffer, logs, protection log).

**What it does:** subscribes to event log channels (Security, System, Application, Sysmon, PowerShell, Defender, Task Scheduler – according to the profile from the panel), renders XML, batches and sends to `siem-ingest`. It watches the log sizes (`logwatch` – warns before Windows overwrites unread events), keeps events in the disk buffer when there is no connection, limits CPU, memory and bandwidth use, sends a heartbeat every minute, protects the service against being stopped.

**Commands** (`vardr-agent help`):

| Command | Action |
|---|---|
| `install [-server address] [-token token] [-profile workstation\|server\|dc] [-start-at now\|oldest] [-no-start]` | install the service; with `-token` enroll in the panel (the agent generates its key) |
| `status` | state of the service, connection, channels, buffer, limits and protection |
| `start`, `restart`, `stop [-token T]` | service control; stopping a protected agent requires a token from the panel |
| `test` | check the connection to the server |
| `set-server <address>` | change the server address (restarts the agent) |
| `upgrade [-token T]` | upgrade the program from the folder of the new version |
| `uninstall [-token T] [-purge]` | uninstall (`-purge` also removes data and certificates) |
| `check` | validate the configuration, certificates and permissions |
| `run` | run in the console instead of as a service (diagnostics) |
| `enroll -server <address> -token <token> -dir <directory>` | enroll without installing the service |
| `version` | version |

Command messages follow the Windows language (English or Polish; to force one: `VARDR_LANG=en|pl`). The `-config <file>` option points to another configuration. The MSI installer (`deploy/lab/msi`) calls the same commands; uninstalling a protected agent via MSI requires `UNINSTALL_TOKEN=`.

**Local configuration** (`agent.yaml`, example: `agent/configs/agent.example.yaml`):

| Key | Meaning |
|---|---|
| `server.url`, `server.panel_url` | ingest address (`https://…:8443/v1/ingest`) and panel address (group configuration) |
| `server.ca_file`, `cert_file`, `key_file`, `timeout` | mTLS certificates |
| `state_dir` | state directory (read bookmarks, buffer) |
| `start_at` | `now` – new events only, `oldest` – from the beginning of the log |
| `batch.max_events`, `max_bytes`, `flush_interval`, `flush_max_wait`, `flush_min_events`, `max_event_bytes` | batching (a small batch below `flush_min_events` waits up to `flush_max_wait`, by default 50 events / 10 s) |
| `limits.priority`, `cpu_max_percent`, `memory_soft_mb`, `memory_hard_mb`, `max_eps`, `max_send_kbps`, `max_procs` | the resource "muzzle" |
| `buffer.max_mb`, `on_full` (`pause`\|`drop_oldest`), `min_free_mb` | disk buffer (1 GB by default) |
| `logging.level`, `max_size_mb`, `max_files` | agent log |
| `channels[].name`, `event_ids` | channels and event identifiers (when the agent gets no profile from the panel); every profile collects Security (range by profile), System, PowerShell 4104, Sysmon and Microsoft Defender (detections, actions, ASR, protection disabled, setting changes) |

The panel overrides channels, limits and protection according to the agent's group (`/enroll/v1/config`, checked every few minutes; `SIEM_CONFIG_POLL_SECONDS` shortens this in tests). The local file decides the server, certificates and state directory. Installation, protection and diagnostics: [agent.md](agent.md).

## siem-collector – syslog collector

Code: `agent/cmd/siem_collector`. An agent in server mode (Linux or Windows; the `collector` container in the stack). It receives syslog (RFC 3164, RFC 5424, plain `<PRI>`) over UDP and TCP and sends the messages like an agent – mTLS, batches, disk buffer, heartbeat, certificate renewal. It does not decode: decoding is done by the normalizer, so a decoder change requires no change on the collector.

```
siem-collector enroll -server <address> -token <token> -ca ca.crt -dir <directory>
siem-collector run -config <directory>/collector.yaml
siem-collector version
```

`collector.yaml`: keys shared with the connector (`server`, `state_dir`, `batch`, `buffer`, `max_eps`) plus `syslog.udp`, `syslog.tcp` (listen addresses, e.g. `:514`), `syslog.max_message_kb`, `syslog.allow` (a list of CIDR networks from which messages are accepted – syslog has no authentication, so the list is recommended). Enrollment: `sudo ./enroll-service.sh collector [group]` on the server.

## siem-connector – API connector

Code: `agent/cmd/siem_connector`. An agent fetching logs from a cloud API. Currently Entra ID via Microsoft Graph: sign-ins (`signIns`, requires Entra ID P1/P2) and directory changes (`directoryAudits`). The read cursor is in the connector state, windows overlap (Graph logs arrive late), the server removes duplicates.

Commands as in the collector (`enroll`, `run -config connector.yaml`, `version`). `entra` keys:

| Key | Meaning |
|---|---|
| `tenant_id`, `client_id`, `client_secret_file` | the application in Entra ID (secret in a separate file) |
| `login_url`, `graph_url` | API addresses (in the lab the `entrasim` simulator) |
| `sign_ins`, `audits` | which logs to fetch (both by default) |
| `interval` (1m), `overlap` (15m), `lookback` (24h) | rhythm, overlap, reach of the first start |

Enrollment: `sudo ./enroll-service.sh connector [group]` on the server.

## siem-ingest

Code: `server/cmd/siem-ingest`, `server/internal/ingest`. The entry point for agents (port 8443, HTTPS with a client certificate).

| Endpoint | Action |
|---|---|
| `POST /v1/ingest` | an event batch (gzip + JSON, contract v1) → `SIEM_RAW`; 200 after NATS confirms |
| `POST /v1/heartbeat` | agent heartbeat → `SIEM_HEARTBEATS` |

Refusals: 429 (too many parallel requests – `SIEM_INGEST_MAX_INFLIGHT`, heartbeats separately `SIEM_INGEST_MAX_HEARTBEATS`), 503 (queue filled above `SIEM_INGEST_QUEUE_HIGH_WATER` or NATS unavailable), 413 (batch too large, also after decompression), 403 (`agent_id` in the batch does not match the certificate). A certificate revoked in the panel is rejected at connection. 429 and 503 refusals have a `Retry-After` header.

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_LISTEN` | `:8443` | listen address |
| `SIEM_TLS_CERT`, `SIEM_TLS_KEY` | `/certs/server.*` | server certificate |
| `SIEM_TLS_CA`, `SIEM_TLS_AGENTS_CA` | `/certs/ca.crt`, `/certs/agents-ca.crt` | CAs the server trusts (root and token enrollment) |
| `SIEM_INGEST_MAX_INFLIGHT` | 64 | parallel batches |
| `SIEM_INGEST_MAX_HEARTBEATS` | 128 | parallel heartbeats (agents coming back en masse) |
| `SIEM_INGEST_QUEUE_HIGH_WATER` | 0.9 | queue fill from which the response is 503 |
| `SIEM_QUEUE_RAW_MAX_MB`, `SIEM_QUEUE_EVENTS_MAX_MB`, `SIEM_QUEUE_MAX_AGE` | 8192, 8192, none | stream limits (shared by the pipeline services) |

Metrics: `siem_ingest_events_total`, `siem_ingest_batches_total{result}`, `siem_ingest_request_seconds`, `siem_ingest_in_flight`, `siem_ingest_queue_fill_ratio`.

## siem-normalizer

Code: `server/cmd/siem-normalizer`, `server/internal/normalize`, `internal/decode`. The `normalizer` consumer on `SIEM_RAW`.

- Windows events: an XML parser (`EvtRender`), `EventData`/`UserData` fields into `fields`, common fields (account, domain, address, process, action, outcome) by event identifier.
- Syslog and API: decoders (built into `internal/decode/builtin` and from the panel through NATS KV `SIEM_DECODERS`). Description: [decoders.md](decoders.md).
- Person (`user_identity`) according to the configuration from NATS KV `SIEM_IDENTITY`.
- Time control: a time out of range or in the future – `time_quality` = `invalid`/`future`, the ingest time instead of the event time.
- Quarantine for events that cannot be normalized (the reason in English).
- Reprocessing quarantine at the panel's request (subject `siem.reprocess`).

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_NORMALIZER_WORKERS` | number of cores | parallel batches |
| `SIEM_PIPELINE` | `live` | `replay` – the copy for replays from the archive (`SIEM_REPLAY_*` streams) |
| `SIEM_SYSLOG_TZ` | `Europe/Warsaw` | time zone for syslog headers without a zone (set in compose) |

Metrics: `siem_normalizer_events_total`, `siem_normalizer_quarantined_total`, `siem_normalizer_batch_seconds`.

## siem-writer

Code: `server/cmd/siem-writer`, `server/internal/chwriter`. The `clickhouse-writer` consumer on `SIEM_EVENTS`. It collects batches and writes them with one INSERT to `siem.events` and `siem.quarantine`; it acknowledges messages after a successful write.

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_CLICKHOUSE_ADDR`, `SIEM_CLICKHOUSE_USER`, `SIEM_CLICKHOUSE_PASSWORD` | `clickhouse:9000`, –, – | connection (`siem_writer` account) |
| `SIEM_WRITER_MAX_ROWS` | 20000 | rows in one INSERT |
| `SIEM_WRITER_FLUSH` | 1s | maximum collection time |
| `SIEM_PIPELINE` | `live` | `replay` – write to `siem.events_replay` |

Metrics: `siem_writer_rows_total`, `siem_writer_insert_seconds`, `siem_writer_pipeline_latency_seconds` (from ingest acceptance to write).

## siem-detector

Code: `server/cmd/siem-detector`, `server/internal/detector`, `internal/detect`, `internal/alerts`. Gjallarhorn: all detection mechanisms ([architecture.md](architecture.md#detection-gjallarhorn), [rules.md](rules.md)). Runs as a single instance (an advisory lock in Saga). Applies the `gjallarhorn` schema migrations, synchronizes the rule list with the panel, removes old alerts.

```
siem-detector serve            service (default)
siem-detector check <dir>      check rules (exit code 1 = errors; output in English)
siem-detector disable          remove the stream consumer
```

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_DETECTOR_DB_URL` | – | Saga (`siem_detector` role) |
| `SIEM_RULES_DIR` | `/rules` | rules directory (`/rules/current`, switched atomically) |
| `SIEM_DETECTION_MODE` | `stream` | `stream`, `index_query` or `both` – which engines run |
| `SIEM_DETECTOR_CH_ADDR`, `_USER`, `_PASSWORD` | `clickhouse:9000`, `siem_detector`, – | ClickHouse for the query engine, correlations and silent sources; without a password – streaming only |
| `SIEM_INDEX_INTERVAL`, `SIEM_INDEX_DELAY` | 1m, 2m | query engine rhythm and delay behind the current time |
| `SIEM_INDEX_LOOKBACK`, `SIEM_INDEX_OVERLAP` | 1h, 5m | reach of the first run and the overlap |
| `SIEM_INDEX_MAX_ROWS` | 100000 | events in one run |
| `SIEM_SOURCE_SILENCE_MIN` | 1h | the shortest silent-source threshold |
| `SIEM_ALERT_RETENTION_DAYS` | 365 | removal of closed alerts (0 = never) |

Metrics: `siem_detector_events_total`, `_matches_total`, `_alerts_total{result}`, `_errors_total{stage}`, `_rules`, `_rule_errors`, `_threshold_keys`, `_eval_seconds_total`, `_index_lag_seconds`, `_index_rows_total`, `_index_runs_total`, `_last_event_timestamp_seconds`.

## siem-archiver

Code: `server/cmd/siem-archiver`, `server/internal/archiver`, `internal/urd`. Urd: the NIS2 archive of original batches. The `archiver` consumer on `SIEM_RAW` (created only when archiving is enabled in the policy). Also: chain verification, retention, auditor exports, replay requests, applying policy changes from the panel (with a delay for weakening), reconciling the catalog with the disk after a database restore and administrator decisions about files unknown to the catalog (`urd.recoveries`, recorded in `archive/recoveries/`). Descriptions stored for the panel follow the system language.

```
siem-archiver serve                     service (default)
siem-archiver verify [--full]           verify the archive now
siem-archiver check-export <file.tar>   check an export package (English report)
siem-archiver disable                   remove the archive consumer
```

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_ARCHIVE_DB_URL` | – | Saga (`siem_archiver` role) |
| `SIEM_ARCHIVE_DIR` | `/archive` | archive directory (mounted from `SIEM_ARCHIVE_PATH`) |
| `SIEM_ARCHIVE_SEGMENT_MB`, `SIEM_ARCHIVE_SEGMENT_AGE` | 64, 30s | segment closing |
| `SIEM_ARCHIVE_RETENTION_DAYS` | 30 | default retention (policy in the panel) |
| `SIEM_ARCHIVE_MIN_RETENTION_DAYS`, `_MAX_RETENTION_DAYS` | 30, 3650 | bounds for the retention set in the panel |
| `SIEM_ARCHIVE_POLICY_GRACE` | 24h | delay of a policy weakening |
| `SIEM_ARCHIVE_VERIFY_EVERY`, `_VERIFY_BUDGET_GB` | 6h, 50 | verification and how many GB to read per run |
| `SIEM_ARCHIVE_MIN_FREE_GB`, `_MIN_FREE_PERCENT`, `_WARN_FREE_PERCENT` | 2, 5, 15 | disk protection: below the minimum archiving pauses (events wait in the queue) |
| `SIEM_ARCHIVE_EXPORT_DIR`, `_EXPORT_TOOLS`, `_EXPORT_KEEP_DAYS` | `/exports`, `/export-tools`, 7 | exports and the `odczytaj.exe` reader |
| `SIEM_ARCHIVE_EXCLUDE_AGENTS` | – | prefixes of agents to skip (e.g. `agt-load-` – the generator) |

Metrics: `siem_archive_*` (segments, bytes, verifications, free space).

## siem-backup

Code: `server/cmd/siem-backup`, `server/internal/backup`, `internal/backupcfg`. Backups according to the panel settings ([operations.md](operations.md#backups)). The `backup` container (an image based on `postgres:18-alpine` with `pg_dump`, gpg, rclone and OpenSSH – `deploy/lab/backup/Dockerfile`) runs as root to read Grafana data and the backup password; it hands the backup files over to the stack user.

```
siem-backup serve     service (default)
siem-backup run       backup now – a request for the running service, waits for the result (./backup.sh)
```

Every 15 s the service records its state in Saga (`backup_runner`), executes requests from the panel (`backup_requests`: backup, connection test, new SSH key) and scheduled backups, one at a time. Results go to `backup_runs` (in the system language), and metrics for Grafana alerts to `metrics/backup.prom`.

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_BACKUP_DB_URL` | – | Saga (`saga_admin` role – `pg_dump` of the whole database) |
| `SIEM_BACKUP_TZ` | `Europe/Warsaw` | schedule time zone |
| `SIEM_BACKUP_DIR`, `_STATE_DIR`, `_PASS_FILE` | `/backup`, `/state`, `/secrets/backup.pass` | local backups, state (keys), backup password |
| `SIEM_BACKUP_STACK_DIR`, `_ARCHIVE_DIR`, `_GRAFANA_DIR`, `_METRICS_DIR` | `/stack`, `/archive`, `/grafana`, `/metrics` | backup sources and metrics |
| `SIEM_BACKUP_UID`, `_GID` | 1000 | owner of the backup files |
| `SIEM_BACKUP_SERVER_NAME` | container name | server name in the backup description |
| `SIEM_BACKUP_REMOTE`, `_REMOTE_KEEP_DAYS` | – | former `.env` settings, moved to the panel at the first start |

## siem-api – Hliðskjálf panel

Code: `panel/cmd/siem-api`, `panel/internal/*`, frontend `panel/web`. An HTTPS backend (port 8444) with the embedded frontend: the panel API (`/api/v1/…`, cookie sessions), agent enrollment and configuration (`/enroll/v1/register|renew|config`), sending notifications from the outbox, synchronizing heartbeats, decoder and identity configuration to NATS. The Grafana alert relay on `SIEM_API_INTERNAL_LISTEN` (stack network only). Modules: [panel.md](panel.md).

```
siem-api                                   server (default)
siem-api bootstrap-admin -username admin   first administrator account (prints the initial password)
siem-api reset-password -username john     a new initial password
siem-api reset-mfa -username john          remove the account's second factor
```

The command messages are in English. On the server: `docker compose run --rm api bootstrap-admin -username admin`.

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_API_DB_URL` | – | Saga (`siem_api` role) |
| `SIEM_API_LISTEN`, `SIEM_TLS_CERT`, `SIEM_TLS_KEY` | `:8444`, `/certs/server.*` | HTTPS |
| `SIEM_CLICKHOUSE_ADDR`, `_USER`, `_PASSWORD` | `clickhouse:9000`, –, – | event search (`siem_panel` account) |
| `SIEM_NATS_URL` | – | NATS (without NATS the panel works, but without heartbeats and configuration delivery) |
| `SIEM_AGENTS_CA_CERT`, `SIEM_AGENTS_CA_KEY`, `SIEM_ROOT_CA` | `/certs/…` | agent CA (issuing certificates) and server CA (for packages) |
| `SIEM_PUBLIC_SERVER` | – | the server address written into installation packages |
| `SIEM_AGENT_EXE` | `/agent-dist/vardr-agent.exe` | the agent program for packages |
| `SIEM_PROMETHEUS_URL` | – | the System health page |
| `SIEM_GRAFANA_URL` | panel server address, port 3000 | the Grafana address for the browser – links to dashboards and alerts in Himinbjörg |
| `SIEM_ARCHIVE_EXPORT_DIR` | – | downloading archive exports |
| `SIEM_ALERT_NOTIFY_PER_RULE`, `SIEM_ALERT_NOTIFY_WINDOW` | 5, 10m | "alert storm": above the limit in the window – a digest message |
| `SIEM_ANCHOR_HOUR`, `SIEM_ANCHOR_TZ` | 7, `Europe/Warsaw` | daily archive anchor to a channel |
| `SIEM_API_INTERNAL_LISTEN`, `SIEM_ALERT_RELAY_TOKEN` | `:8081`, – | relay of Grafana alerts to panel channels |
| `SIEM_SYSLOG_TZ` | `Europe/Warsaw` | decoder tests in the panel |
| `SIEM_API_TOKEN_RATE` | 600 | limit of requests per minute for one API token (a short burst above it is allowed; above the limit – 429) |
| `SIEM_API_TOKEN_LOG_DAYS` | 30 | how long the panel keeps the request history of API tokens |

## siem-loadgen

Code: `server/cmd/siem-loadgen`, `server/internal/loadgen`. A traffic generator: simulates thousands of agents with a realistic event mix. Usage and the test procedure are described in Polish: [testy-obciazeniowe.md](../testy-obciazeniowe.md).

## Tools

| Program | Code | Purpose |
|---|---|---|
| `siem-pki` | `tools/cmd/siem-pki` | lab certificates: `ca`, `server [-hosts]`, `agents-ca`, `agent [-id]`, `package -id … [-server]` (an installation package with a key). Lab only – production agents enroll with a token. |
| `siem-ingest-stub` | `tools/cmd/siem-ingest-stub` | a test `/v1/ingest` writing events to an NDJSON file (`-listen :8443 -out data/events.ndjson`); for testing the agent without a server |
| `fortisim` | `tools/cmd/fortisim` | a FortiGate syslog simulator: `-target 192.168.88.98:514 -proto udp\|tcp -scenario traffic\|portscan\|sweep\|vpn-ok\|vpn-brute\|vpn-spray\|admin-brute\|utm\|mix -count N -every 100ms -user -attacker -header bare\|rfc3164\|rfc5424 -dry` |
| `entrasim` | `tools/cmd/entrasim`, `internal/entrasim` | a Microsoft Graph simulator (`entrasim` container): background sign-ins and scenarios on demand – `curl -X POST 'http://127.0.0.1:8099/sim/scenario?name=spray'`; scenarios `normal`, `spray`, `brute`, `success-after-failures`, `foreign`, `mfa-fatigue`, `admin-role` (parameters `user=`, `attacker=`) |
| `attackgen` | `tools/cmd/attackgen` | the MITRE ATT&CK dictionary from the official STIX bundle: `go run ./tools/cmd/attackgen enterprise-attack.json > internal/attack/enterprise.json` |
| `odczytaj` | `tools/cmd/odczytaj` | the archive export reader for auditors (Windows, no installation): checks the package integrity and writes a report and the events of each day into the `ODCZYT` subfolder – in English or Polish according to the Windows language (`VARDR_LANG`) |

Building: [development.md](development.md#building).
