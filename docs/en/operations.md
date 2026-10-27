# Operations

This document covers a running Vardr server: layout, deployment, agents, backups, retention, migrations, monitoring and diagnostics. A server installed from the bundle lives in `/opt/vardr` (stack files) and `/srv/vardr` (archive, exports, backups); the development lab (`deploy/lab`, deployed with `deploy.sh`) uses `~/siem-lab` instead – where the two differ, both are given. Installing from the bundle: [installation.md](installation.md).

## Server layout

| Location | Content |
|---|---|
| `/opt/vardr/` (lab: `~/siem-lab/`) | the stack: `docker-compose.yml`, scripts, database init, Prometheus, Grafana and NATS configuration |
| `.env` in the stack directory | passwords and settings (only on the server, encrypted in backups) |
| `certs/` | server CA, server certificate, agent CA with its key (issuing certificates at enrollment), `mfa.key` |
| `bin/` | Linux programs |
| `rules/` | rules: `v<time>/` and the `current` link |
| `collector/`, `connector/` | configuration, certificates and buffer of the collector and connector |
| `/srv/vardr/archive` | NIS2 archive (`SIEM_ARCHIVE_PATH`, preferably a separate disk) |
| `/srv/vardr/backup` | backups before upload (`SIEM_BACKUP_DIR`) |
| backup password file | `VARDR_BACKUP_PASS_FILE` in `.env` (installer: `/etc/vardr/backup.pass`; lab: `~/.vardr-backup.pass`), owner only |
| Docker volumes | NATS, ClickHouse, Saga, Prometheus, Grafana data |

**`.env` variables:** database passwords (`SAGA_ADMIN_PASSWORD`, `SAGA_DB_PASSWORD`, `SAGA_ARCHIVER_PASSWORD`, `SAGA_DETECTOR_PASSWORD`, `CLICKHOUSE_ADMIN_USER`/`_PASSWORD`, `CLICKHOUSE_WRITER_PASSWORD`, `CLICKHOUSE_PANEL_PASSWORD`, `CLICKHOUSE_DETECTOR_PASSWORD`, `CLICKHOUSE_GRAFANA_PASSWORD`), `GRAFANA_ADMIN_PASSWORD`, `SIEM_ALERT_RELAY_TOKEN`, `SIEM_PUBLIC_SERVER` (the address in agent packages), `SIEM_EVENTS_TTL_DAYS`, `SIEM_RAW_TTL_DAYS`, `SIEM_ARCHIVE_PATH`, `SIEM_ARCHIVE_EXPORT_PATH`, `SIEM_DETECTION_MODE`, `SIEM_BACKUP_REMOTE`, `SIEM_PPROF`. Other service settings have defaults in the compose file ([programs.md](programs.md)).

**Ports:**

| Port | Service | Access |
|---|---|---|
| 8443 | `siem-ingest` (agents, mTLS) | network |
| 8444 | panel | network |
| 514 UDP/TCP | syslog collector | network (`allow` list) |
| 3000 | Grafana | network |
| 9090 | Prometheus | server only (`ssh -L 9090:127.0.0.1:9090`) |
| 8123 | ClickHouse HTTP | server only |
| 8222 | NATS monitoring | server only |
| 4222, 9000, 5432, 9100, 8081 | NATS, ClickHouse, Saga, metrics, alert relay | Docker network only |

## Deployment

**Installed server:** upgrades come from a new bundle – `sudo ./install.sh` (see [installation.md](installation.md#upgrade)). The stack is managed by the `vardr` systemd service (`sudo systemctl restart vardr`).

**Lab:** the only way to change the lab server is `deploy/lab/deploy.sh` from the workstation (Git Bash), so the VM does not drift from the repository.

```bash
deploy/lab/deploy.sh                    # config, rules and server services (without web, agent, collector, connector, tools)
deploy/lab/deploy.sh detector api       # selected targets
```

| Target | Action |
|---|---|
| `config` | stack files from `deploy/lab` (without `certs/`, `.env`, `bin/`, data); crontab `@reboot boot.sh`; backup password file and `backup-state/` |
| `rules` | rules (checked before sending), atomic switch |
| `web` | the panel frontend built in a Node container on the VM (then the `api` target) |
| `ingest`, `normalizer`, `writer`, `archiver`, `detector`, `api`, `backup` | a Linux program with the git version, image and service restart |
| `collector`, `connector` | the collector and connector |
| `agent` | `vardr-agent.exe` and the MSI for panel packages |
| `tools` | `odczytaj.exe` for archive exports |

Variables: `SIEM_LAB_HOST` (`siem@192.168.88.98`), `SIEM_LAB_KEY` (`~/.ssh/siem_lab`), `SIEM_LAB_DIR` (`~/siem-lab`). A version with uncommitted changes has the `-dirty` suffix.

**Order:** `gjallarhorn` schema changes are applied by the detector, so deploy **the detector before the panel**. A `docker-compose.yml` change requires `deploy.sh config` and then `docker compose up -d` on the VM (recreates changed containers). A JetStream limit change (`nats/nats.conf`) requires `docker compose restart nats`, and a Grafana alert change – a Grafana restart.

**Start after a VM restart (lab):** `boot.sh` (crontab `@reboot`) runs `docker compose up -d` 30 s after system start; log in `~/siem-lab/boot.log`. An installed server uses the `vardr` systemd service instead.

## Agents

- **New agent:** panel → Bifröst → token and MSI or ZIP package. On the computer double-click the MSI or `vardr-agent install -token …`.
- **Upgrade:** a new MSI version (every release must have a new version number – the installer does not upgrade the same version). A protected agent accepts an upgrade via the installer without a token (the installer stops it as SYSTEM).
- **Stop, uninstall:** panel → agent → Uninstall token (password re-entry, reason). The token is single-use and short-lived.
- **Revocation:** panel → agent → Revoke. The certificate goes to the list rejected by ingest, and the lost-contact alert skips the agent.
- **Collector and connector:** `sudo ./enroll-service.sh collector|connector [group]` on the server (lab: `deploy/lab/service-enroll.sh` from the workstation), once after the first deployment.
- **Audit policy and Sysmon in the domain:** `deploy/windows/vardr-gpo.ps1`, `deploy/windows/sysmon.ps1`.

## Backups

Backups are made by the `siem-backup` service (`backup` container) and configured in the panel: **Administration → Backups**.

| Setting | Options |
|---|---|
| schedule | every 1–12 hours, daily or weekly at a given hour (server time) |
| contents | Saga database, configuration (`certs/` with the agent CA key, `.env`), NIS2 archive increments (destination only), Grafana data |
| retention | separately locally and at the destination: days and at most N backups (0 – no limit); the newest backup always stays; archive packages expire only by days |
| destination | local only, SFTP (a key generated by the service, your own key or a password), SMB, S3 (MinIO, AWS, Backblaze…) |

**How it works:**

- The panel stores the settings in Saga (always with password re-entry, audited). The service checks them every 15 s.
- Passwords and keys for the destination are encrypted by the panel with the service's public key, so neither the panel nor the database can read them.
- A backup is a package `vardr-YYYYMMDD-HHMM-k<id>.tar.gpg` encrypted with the backup password (gpg AES-256). Locally it lies in `SIEM_BACKUP_DIR` (default `/srv/vardr/backup`), at the destination in `config/`, and archive increments in `urd/`. Each backup contains `KOPIA.txt` describing it in Polish and English.
- Uploads go through rclone. The SFTP server key is remembered at the first connection (the fingerprint is shown in the panel); a later change stops uploads. To accept a new key, remove the entry from `backup-state/known_hosts`.
- The panel shows the backup history with results and has "Back up now" and "Check connection" buttons. Result messages are written in the system language.
- The service state (secrets key, SSH key, `known_hosts`) is in `backup-state`. Losing this directory means new keys: secrets have to be entered again, and the new SSH key added on the backup server.

**Restore from the panel** (*Restore* tab):

1. **Backup list.** The panel shows local backups and those at the destination; the list refreshes every 15 min and after every backup.
2. **Content check.** The service decrypts the backup with the backup password (a backup from the destination is downloaded first) and shows what it contains.
3. **Restore.** The administrator chooses the parts to restore: the Saga database together with the configuration (`.env` holds the database role passwords) and/or Grafana data. They confirm by typing `RESTORE` (or `PRZYWRÓĆ`) and the password.
4. **Preparation.** The backup service makes a backup of the current state (by default), checks the backup and leaves a request in `<backups>/.przywracanie/zlecenie`.
5. **Restore.** `restore.sh --zlecenie` (systemd timer `vardr-restore.timer`; lab: cron every minute) stops the services using the database (panel, detector, archiver, backup service), restores the parts and starts the stack. It stores the result in Saga (in the system language), and the log in `restore.log`.

After a database restore the panel is as on the backup date: accounts and sessions too, so you need to sign in again. Alerts, agents and setting changes later than the backup disappear. A restore does not change events in ClickHouse or the NIS2 archive; the archive is restored manually on a clean server (`restore.sh <backup> <urd directory>`). The backup service has no Docker access – only the script on the server can stop services.

**The NIS2 archive after a database restore.** The archive catalog (`urd` schema) goes back to the moment of the dump, while segments and manifests written later stay on disk without an entry – verification would report them as "added outside the archiver". Therefore:

1. After restoring the database, `restore.sh` leaves a request in `urd.recoveries` with a time window: from the dump (time from the dump header, 10 min margin) to the restore.
2. At start, before closing the next hour, the archiver adopts files from that window into the catalog: a manifest – when it extends the chain (number, hour, previous hash) and its segments have matching hashes; a segment without a manifest – when the format and the SHA-256 of all batches match (it goes into the nearest manifest). Then it verifies the archive immediately.
3. Files outside the window, damaged or without proof of continuity remain reported. In the panel (*Urd*) the administrator decides about them: **adopt into the archive** (the same checks) or **move to quarantine** (`archive/quarantine/<time>/…`, the file is kept outside the chain). The decision requires a reason and the password.

Nothing is deleted or rewritten: the result of the verification that found the inconsistency stays in the history, and every operation is a separate entry (*Inconsistency handling* tab, panel audit) and a file in `archive/recoveries/` – which survives further database restores and goes into the auditor export (`obsluga-niezgodnosci/`).

```bash
./backup.sh                    # backup now (request for the service, waits for the result)
./backup.sh password init      # first password (shown once – write it down outside the server)
./backup.sh password show | change
./restore.sh <vardr-….tar.gpg> [directory with urd-… packages]   # restore on a clean VM
./restore.sh --zlecenie        # restore requested in the panel (run by the timer)
```

A backup does not contain events in ClickHouse (a few days, can be replayed from the archive) or NATS queues (agents resend pending events themselves). Grafana alerts check whether a backup was made and left the VM within 26 h.

## Retention

| Data | Setting | How to change |
|---|---|---|
| events and quarantine in ClickHouse | `SIEM_EVENTS_TTL_DAYS` | `.env`, then `./clickhouse/retention.sh` |
| selected event datasets (`event.dataset`) | `SIEM_EVENTS_TTL_DATASETS`, e.g. `fortigate.=3,windows.security=30` (prefix=days) | as above; the installer applies it on upgrade |
| raw event XML | `SIEM_RAW_TTL_DAYS` (≤ events) | as above |
| sign-in table | successful Windows sign-ins 1 day, the rest as events | `retention.sh` |
| replayed events | `SIEM_REPLAY_TTL_DAYS` (7) | compose |
| NIS2 archive | policy in the panel (Urd), bounds `SIEM_ARCHIVE_MIN/MAX_RETENTION_DAYS` | panel (shortening with a 24 h delay) |
| closed alerts | `SIEM_ALERT_RETENTION_DAYS` (365) | compose |

**Retention per dataset.** A prefix matches the beginning of the dataset name (`fortigate.` covers `fortigate.traffic`, `fortigate.event`…), the longest matching prefix wins, datasets without a rule use `SIEM_EVENTS_TTL_DAYS`. Typically: firewall traffic (the largest, of little use after a few days) shorter, sign-ins and account changes longer. New rules apply to new data at once; data written earlier expires under the old rules until its parts are merged – `./clickhouse/retention.sh --materialize` applies the rules to everything at once (rewrites the whole table). Data is removed in the background, when parts are merged (up to a few hours after the deadline). The NIS2 archive has one retention for all sources.

Disk planning: about 125 B per event in ClickHouse with raw XML (about 75 GB a day at 7,000 events/s), the archive about 120 B per event (about 100 GB a day at 10,000/s).

## Migrations

- **Saga:** automatic at service start (`siem-api` – `public`, `siem-detector` – `gjallarhorn`, `siem-archiver` – `urd`), under an advisory lock.
- **ClickHouse – new installation:** the `clickhouse/init/*.sh` scripts at the first start (empty volume).
- **ClickHouse – existing database:** the init scripts are safe to run again:

  ```bash
  docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/02-replay.sh
  docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/03-auth-events.sh
  ```

  Changing the sorting key of `siem.events` (old installations): `bash clickhouse/events-order.sh`.

## Monitoring

- **Grafana** (`:3000`): dashboards "SIEM – event overview" and "SIEM – pipeline health" (flow through the stages, rejections, queues, lags, service CPU and memory, ClickHouse).
- **Grafana alerts** (`grafana/provisioning/alerting/vardr.yaml`): pipeline not working, detector not running, archiver not running, NATS queue > 80%, ingest rejecting, query engine > 15 min behind, rules with errors, archive (inconsistencies, no verification, low space, archiving disabled, scheduled weakening), system disk, backups. Alerts go through the panel relay to notification channels, with the summary and description in the system language (`summary_en`/`description_en` annotations).
- **Panel → Himinbjörg:** state of services and queues.
- **Logs:** `docker compose logs --since 10m <service>`; warnings and errors: `… | grep -E '"WARN"|"ERROR"'`. Service logs and server script messages are in English.

## Diagnostics

| Symptom | Where to look | Typical cause |
|---|---|---|
| agents get 503 | NATS queue (`siem_queue_fill_ratio`), consumer backlog | a stopped stage (writer, archiver), full archive disk |
| backlog grows at constant traffic | monitor (`pending`), CPU | the VM is saturated; ClickHouse query log (what reads the most) |
| query engine behind | `siem_detector_index_lag_seconds`, detector log | overloaded ClickHouse, a mass attack on the same accounts |
| no alerts from a rule | panel → Rules (errors, disabled?), rule test | an error in the rule, a wrong `logsource`, a field with a different name |
| syslog events as `syslog.generic` | Mímir `dataset:syslog.generic` | no decoder for the device |
| quarantine grows | panel → Quarantine | the device changed its log format, a decoder error |
| agent "stopped without a token" | agent page, tampering alert | someone stopped the service; check the protection log |
| ClickHouse `MEMORY_LIMIT_EXCEEDED` | `system.query_log` (`exception_code = 241`) | an overly broad query, a `DELETE` mutation on a big table |
| services did not start after a restart | `systemctl status vardr`, `docker compose ps` (lab: `boot.log`) | Docker did not bring a container up |

ClickHouse and Saga commands on the server:

```bash
docker compose exec clickhouse bash -c 'clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD"'
docker compose exec saga psql -U saga_admin -d saga
docker run --rm --network siem_default natsio/nats-box:0.18.1 nats -s nats://nats:4222 stream ls
```
