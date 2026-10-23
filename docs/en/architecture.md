# Architecture

Vardr is a set of small Go programs connected by a NATS JetStream queue. Events pass through successive stages, and each stage acknowledges a message only after doing its work. A failure or restart of any service therefore does not lose events: they wait in the queue, and the agents keep them in a disk buffer until the server accepts them.

## Components

```
 Windows computers          network devices                 cloud
 ┌──────────────┐           ┌──────────────┐               ┌────────────┐
 │ vardr-agent  │           │ MikroTik,    │──syslog 514──▶│siem-       │
 │ (service)    │           │ FortiGate    │               │collector   │
 └──────┬───────┘           └──────────────┘               └─────┬──────┘
        │ HTTPS + mTLS, gzip batches, heartbeat                  │   ┌────────────┐
        │                                                        │   │siem-       │◀── Microsoft Graph
        ▼                                                        ▼   │connector   │    (Entra ID)
 ┌───────────────────────────── siem-ingest :8443 ◀──────────────────┴────────────┘
 │  /v1/ingest → SIEM_RAW (batch unchanged)
 │  /v1/heartbeat → SIEM_HEARTBEATS
 ▼
 SIEM_RAW ──▶ siem-normalizer ──▶ SIEM_EVENTS ──┬──▶ siem-writer ──▶ ClickHouse siem.events (+ quarantine)
    │                                           │                       └─ view → siem.auth_events
    │                                           └──▶ siem-detector (stream) ──▶ Saga: gjallarhorn.*
    └──▶ siem-archiver ──▶ NIS2 archive (files)      siem-detector (queries, correlations) ◀── ClickHouse
                                                                     │
 siem-api (Hliðskjálf panel :8444) ◀── Saga, ClickHouse, NATS ◀──────┘ (outbox → Discord/webhook)
 Prometheus ◀── :9100 metrics of all services ──▶ Grafana :3000 (dashboards, alerts)
```

| Program | Role | State |
|---|---|---|
| `vardr-agent` (Windows) | reads event logs, sends batches, protects itself against being stopped | read state and disk buffer in `C:\ProgramData\SiemAgent` |
| `siem-collector` | receives syslog from devices, sends like an agent | disk buffer in the collector directory |
| `siem-connector` | fetches logs from a cloud API (Entra ID via Graph), sends like an agent | read cursor and buffer |
| `siem-ingest` | accepts batches and heartbeats (mTLS), puts them into NATS | stateless |
| `siem-normalizer` | turns raw events into the common model, decodes syslog and API | stateless (decoders and identities from NATS KV) |
| `siem-writer` | writes events to ClickHouse | stateless |
| `siem-detector` | streaming detection, query engine, correlations, built-in rules | alerts and threshold state in Saga |
| `siem-archiver` | NIS2 archive: original batches in segments with a hash chain | archive files, catalog in Saga (`urd`) |
| `siem-api` | web panel and API, agent enrollment, sending notifications | Saga (`public` schema) |
| `siem-backup` | backups according to the panel settings: Saga, configuration, NIS2 archive, Grafana; upload via SFTP/SMB/S3 | keys in `backup-state/`, results in Saga |

Details of each program: [programs.md](programs.md).

## Languages

Service logs and server command-line output are in English. Texts for people are bilingual: the panel follows the account language (translation files in the browser), rules and alerts store their texts in both languages, and content the server creates for outside the panel (notifications, NIS2 drafts, backup and archive results) follows the **system language** – a panel setting (`panel_settings`, view `system_language` readable by the archiver and backup roles). Command-line programs on Windows (agent, export reader) follow the Windows language. Shared helpers: `internal/lang` (`Pick`, `Errorf` – an error with Polish and English text, `OS`), `internal/lang/langdb` (system language for services).

## Event flow

1. **The agent** reads an event from the Windows log (EvtSubscribe, with a bookmark on the last record), renders the XML and appends it to a batch. The batch is sent when it collects `max_events` events or after a timeout. A small batch (below 50 events) is held up to 10 s, so that low-traffic workstations do not send thousands of tiny batches. The batch goes gzipped over HTTPS with a client certificate (mTLS). Until the server acknowledges it, it sits in the disk buffer.
2. **siem-ingest** checks the certificate (issued by the agent CA and not revoked – list in NATS KV `SIEM_REVOKED_CERTS`), the size and schema of the batch, and publishes it unchanged to the `SIEM_RAW` stream (subject `siem.raw.<agent>`). It responds 200 only after NATS confirms the write. With a full queue it responds 503, with too many parallel requests 429; the agent retries with a delay.
3. **siem-normalizer** (consumer `normalizer` on `SIEM_RAW`) unpacks the batch and turns each event into a `model.Event`: Windows XML with a field-mapping parser, syslog and API with decoders (`internal/decode`). It determines the person (`internal/identity`). Events that cannot be normalized go to quarantine together with the original and the reason. The result is published as a normalized batch to `SIEM_EVENTS` (`siem.events.<agent>`).
4. **siem-writer** (consumer `clickhouse-writer` on `SIEM_EVENTS`) collects batches up to 20,000 rows or 1 s and writes them with one INSERT to `siem.events` and `siem.quarantine`. A materialized view puts sign-ins into `siem.auth_events`.
5. **siem-detector** (consumer `detector` on `SIEM_EVENTS`) evaluates every event with streaming rules. Separately, every minute it queries ClickHouse (query engine and correlations), every 30 s it checks agent heartbeats, every 5 min silent sources. It stores alerts in Saga; a new alert gets an entry in `gjallarhorn.outbox`.
6. **siem-archiver** (consumer `archiver` on `SIEM_RAW`) writes the original batches into archive segments and acknowledges messages only after the segment is written to disk.
7. **siem-api** sends outbox entries to notification channels, and the panel reads events from ClickHouse and alerts from Saga.

The agent heartbeat (every minute: version, channel state, buffer, limits, protection) goes through `/v1/heartbeat` to the `SIEM_HEARTBEATS` stream. The panel (`fleetsync`) updates the agent state from it, and the detector evaluates lost contact and tampering.

### Delivery guarantee

- The agent removes events from the buffer only after a 200 response, and the server responds 200 only after the write to NATS. The log read bookmark moves after the acknowledgement.
- Every stage acknowledges a message after doing its work, so after a failure the message comes back. Duplicates are possible, losses are not.
- Duplicates are removed by ClickHouse (`ReplacingMergeTree`, the key contains `event_id`), detection (a rule–event pair goes into an alert once) and the archive (batch identifier).
- A stopped consumer (e.g. the archiver) blocks removing messages from the queue – the streams have "interest" retention. When the queue fills up, ingest responds 503, and the agents wait with their buffers.

## NATS JetStream

| Stream | Subjects | Consumers | Content |
|---|---|---|---|
| `SIEM_RAW` | `siem.raw.<agent>` | `normalizer`, `archiver` | agent batches unchanged (gzip + JSON, contract v1) |
| `SIEM_EVENTS` | `siem.events.<agent>` | `clickhouse-writer`, `detector` | normalized batches (`model.Batch`, gzip + JSON) |
| `SIEM_HEARTBEATS` | `siem.heartbeat.<agent>` | panel (`fleetsync`) | the last heartbeat of each agent |
| `SIEM_REPLAY_RAW`, `SIEM_REPLAY_EVENTS` | `siem.replay.raw.>`, `siem.replay.events.>` | `normalizer-replay`, `writer-replay` | replay from the archive into `siem.events_replay` |

Key–value stores (NATS KV):

| Store | Written by | Read by | Content |
|---|---|---|---|
| `SIEM_DECODERS` | panel | normalizers | syslog decoders changed in the panel |
| `SIEM_IDENTITY` | panel | normalizers, archiver | organisation domains, account aliases, shared accounts |
| `SIEM_REVOKED_CERTS` | panel | ingest | revoked agent certificates |

The `siem.reprocess` subject (request–reply): the panel asks the normalizer to reprocess a quarantine entry.

Queue limits: `SIEM_QUEUE_RAW_MAX_MB`, `SIEM_QUEUE_EVENTS_MAX_MB` (8 GB each by default), `SIEM_QUEUE_MAX_AGE`. NATS server configuration: `deploy/lab/nats/nats.conf` (`max_file_store` 21 GB – the stream reservations must fit in it).

## Data stores

### ClickHouse (database `siem`)

| Table | Engine | Key / partitions | Retention | Content |
|---|---|---|---|---|
| `events` | ReplacingMergeTree(ingested) | `ORDER BY (event_dataset, toStartOfHour(ingested), host_name, timestamp, event_id)`, daily partition by `ingested` | `SIEM_EVENTS_TTL_DAYS`, raw XML `SIEM_RAW_TTL_DAYS` | normalized events |
| `quarantine` | MergeTree | `(ingested, agent_id)` | as events | unnormalized events with the original |
| `auth_events` | ReplacingMergeTree | `(outcome, event_dataset, ingested, event_id)` | successful Windows sign-ins 1 day, the rest as events | sign-ins (for correlations), fed by the `auth_events_mv` view |
| `events_replay` | ReplacingMergeTree | as `events` | `SIEM_REPLAY_TTL_DAYS` (7) from the replay | events replayed from the archive |

Schema: `deploy/lab/clickhouse/init/` (scripts run at the first start; on an existing database – see [operations.md](operations.md#migrations)). `events` columns: event and ingest time, `event_id`, `agent_id`, `event_dataset`, `event_code`, `event_provider`, `event_action`, `event_outcome`, `host_name`, `user_name`, `user_domain`, `user_identity`, `source_ip` (IPv6, IPv4 as `::ffff:`), process and command line, `message`, `fields` (map of source fields), `raw` (the original), `truncated`, `parser_version`, `time_quality`.

ClickHouse accounts: `siem_writer` (write), `siem_detector` (read with time and memory limits), `siem_panel` (read, 30 s limit, 1–2 GB of memory, 100,000 result rows), `grafana` (read).

### PostgreSQL – Saga

| Schema | Migration owner | Tables |
|---|---|---|
| `public` | `siem-api` (`panel/internal/api/store/migrations`) | `users`, `sessions`, `audit_log`, `panel_settings` (+ view `system_language`), `agents`, `agent_groups`, `agent_assignments`, `agent_certs`, `enrollment_tokens`, `agent_uninstall_tokens`, `notify_channels`, `notify_log`, `syslog_decoders`, `syslog_decoder_versions`, `quarantine_jobs`, `quarantine_outcomes`, `identity_domains`, `identity_aliases`, `identity_shared_accounts`, `incidents` and related tables, `backup_config`, `backup_secrets` (encrypted with the backup service key), `backup_runner`, `backup_runs`, `backup_requests` |
| `gjallarhorn` | `siem-detector` (`internal/alerts/migrations`) | `alerts` (with `i18n`), `alert_events`, `alert_activity`, `outbox`, `threshold_events`, `index_state`, `rules` (with `i18n`), `rule_versions`, `rule_overrides`, `rule_errors` (with `error_en`) |
| `urd` | `siem-archiver` (`internal/urd`) | `segments`, `manifests`, `verifications`, `policy`, `policy_changes`, `exports`, `replays`, `recoveries`, `group_membership`, `archiver_state` |

Each service connects with its own role with minimal privileges (`saga_admin` only for migrations and administration, `siem_api`, `siem_detector`, `siem_archiver`). Migrations are applied by the service at start, under an advisory lock, so several replicas will not run them in parallel. Deployment order: the detector first (the `gjallarhorn` schema), then the panel.

### NIS2 archive (Urd)

Files in `SIEM_ARCHIVE_PATH` (e.g. `/srv/vardr/archive`): original agent batches in segments (up to 64 MB or 30 s), each segment with a SHA-256 hash; hourly manifests list the segments and the hash of the previous manifest (a chain). Every day the hash of the latest manifest goes to a notification channel as an anchor outside the system. Verification every 6 h checks part of the archive within a read budget. The auditor export is a `.tar` package with the `odczytaj.exe` reader. Replay pushes selected segments through a separate pipeline into `siem.events_replay`.

## Detection (Gjallarhorn)

`siem-detector` has several mechanisms writing alerts to the same database:

| Mechanism | What it does | How often | Alert `engine` |
|---|---|---|---|
| streaming engine | Sigma rules on every event from `SIEM_EVENTS`; thresholds in memory (state in `threshold_events`, restored after a restart) | continuously | `stream` |
| query engine | the same rules as SQL on `siem.events` (events ingested since the checkpoint, with overlap); catches up after outages, late events and threshold memory limits | every minute, 2 min behind the current time | `index_query` |
| correlations | built-in ("success after failures", "new country") on `siem.auth_events`; Sigma correlation rules on `siem.events` | every minute | `correlation` |
| lost contact | agent heartbeat older than the group threshold | every 30 s | `system` |
| agent tampering | protection log from the heartbeat, stops without a token | every 30 s | `system` |
| silent source | a syslog device or the cloud is silent longer than usual | every 5 min | `system` |

Recording an alert (`internal/alerts`):

1. **Reservation.** A (rule, event) pair is reserved in `alert_events`, so a redelivered event or the same event from both engines does not count twice.
2. **Merging.** A hit with a group key (`group_by`) merges with an open alert of that rule and key within the `suppress` window. The `hits` counter grows, the event joins the alert timeline.
3. **New alert.** When there is no open alert to merge with, a new alert is created with an outbox entry. Its title, summary and instructions are stored in both languages (`i18n`).

Parallel writes from different mechanisms wait for each other only for the same key (transaction advisory locks). The panel sends outbox entries to the channels (Discord, webhook, with a level filter and an "alert storm" limit).

Writing rules: [rules.md](rules.md).

## Panel and fleet management

- An agent enrolls with a one-time token from the panel (`/enroll/v1/register`): it generates its key itself, the panel issues a certificate signed by the agent CA. Before expiry the certificate is renewed (`/enroll/v1/renew`).
- The agent fetches its configuration (event profile, limits, protection, uninstall tokens) from the panel (`/enroll/v1/config`) according to its group and keeps a local copy.
- Revoking an agent in the panel goes to NATS KV, which ingest reads – from that moment the agent's batches are rejected.
- Panel modules: [panel.md](panel.md).

## Security

- **mTLS everywhere from the agent:** the server accepts only certificates from the agent CA, the agent checks the server certificate against its own CA.
- **Passwords and secrets** are in `.env` on the server (outside the repository) and in gpg-encrypted backups. The database holds only hashes of passwords (argon2id), enrollment tokens and uninstall tokens.
- **Database roles** have minimal privileges; the panel reads ClickHouse with a read-only account with limits, query values are passed as parameters.
- **Sensitive panel operations** (weakening the archive policy, disabling a rule, an uninstall token) require password re-entry and are audited; weakening the archive takes effect with a 24-hour delay.
- **Agent protection:** a service with narrowed permissions, one-time stop and uninstall tokens, a log of attempts in the heartbeat, an alert on tampering.
- **NIS2 archive:** hash chain, a daily anchor outside the system, periodic verification.

## Repository structure

One Go module (`siem`). Code in `agent/internal/`, `server/internal/` and `panel/internal/` is private to its part (Go does not allow importing it from another). Shared packages are in `internal/`.

```
agent/
  cmd/vardr-agent/       Windows agent: installer, service, protection, commands
  cmd/siem_collector/    syslog collector (Linux/Windows)
  cmd/siem_connector/    API connector (Entra ID via Microsoft Graph)
  configs/               agent.example.yaml, agent.lab.yaml
  internal/              config, core (batching), shipper (HTTPS + mTLS), spool (disk
                         buffer), winevt (Event Log), logwatch, sysmon, syslog, graph,
                         hostagent (shared skeleton of the collector and connector), managed
                         (configuration from the panel), enrollment, heartbeat, guard (protection),
                         limits, logging, secure, setup, state, status, timesync, source
server/
  cmd/                   siem-ingest, siem-normalizer, siem-writer, siem-detector,
                         siem-archiver, siem-backup, siem-loadgen
  internal/              bus (NATS), queue, ingest, normalize, chwriter, detector,
                         archiver, backup, loadgen, metrics
panel/
  cmd/siem-api/          panel backend with the embedded frontend
  internal/              api (+ store: Saga, migrations), events (Mímir), enroll (certificates),
                         fleetsync (heartbeats), notify (channels), status (system health),
                         syslang (system language)
  web/                   frontend: React + TypeScript + Mantine (Vite), translations in src/locales
internal/                contract (agent → server batch), model (event), decode
                         (syslog/API decoders, built-in ones in builtin/), decodekv, detect
                         (Sigma rules, SQL), alerts (alerts in Saga), identity, fleet,
                         urd (archive), lang (languages), reprocess, svc, throttle, windesc, entrasim
tools/cmd/               siem-pki, siem-ingest-stub, fortisim, entrasim, odczytaj, attackgen
rules/                   detection rules (windows/, network/, cross/, correlation/)
deploy/lab/              lab stack: docker compose, scripts, database init, Grafana,
                         Prometheus, NATS, MSI
deploy/vardr/            installation bundle: install.sh, build-bundle.sh, sigmahq-import.sh
deploy/windows/          audit GPO, Sysmon installation
docs/                    documentation (Polish; English in docs/en)
```

Local directories outside the repository: `bin/` (programs), `certs/` (lab certificates), `dist/` (agent packages with keys, bundles), `data/` (test data).
