# Installing the Vardr server

The Vardr server is installed from the bundle `vardr-<version>-linux-amd64.tar.gz`: programs, Docker Compose stack files, detection rules, the Windows agent and the `install.sh` script. Service images are built locally from the programs in the bundle; only the base images (NATS, ClickHouse, PostgreSQL, Grafana, Prometheus) are downloaded.

## Requirements

| | Minimum | Recommended |
|---|---|---|
| System | Linux x86_64 with systemd (Debian 12/13, Ubuntu 24.04) | |
| Docker | Docker Engine with the compose plugin 2.20+ ([instructions](https://docs.docker.com/engine/install/)) | |
| Memory | 4 GB | 8 GB or more |
| Disk (Docker directory) | 20 GB | 60 GB or more (queues, event database) |
| NIS2 archive | | a separate disk for `/srv/vardr` |

Ports: `8443/tcp` (agents), `8444/tcp` (panel), `3000/tcp` (Grafana), optionally `514/udp+tcp` and `6514/tcp` (syslog collector, TLS) – who may reach them: [Firewall](#firewall).

## Installation

Download the bundle and `SHA256SUMS` from the [latest release](https://github.com/Azujo/Vardr/releases/latest) (or build it yourself – below) and check the checksum: `sha256sum -c --ignore-missing SHA256SUMS`.

```bash
tar xzf vardr-<version>-linux-amd64.tar.gz
cd vardr-<version>-linux-amd64
sudo ./install.sh
```

The installer asks for the server addresses (the DNS names and IPs agents and browsers use to connect; the first one goes into the agent packages) and the data directory. Without questions: `sudo ./install.sh --server siem.company.com,10.0.0.5 --yes`. Options: `--dir` (stack files, default `/opt/vardr`), `--data` (archive, exports, backups, default `/srv/vardr`), `--admin` (first panel account, default `admin`).

What it does:

1. checks the system (Docker, memory, space, free ports) and installs missing tools (openssl, gpg, curl);
2. creates the `vardr` system user – the owner of the files, under which the services run;
3. copies the stack to `/opt/vardr`, creates `.env` with random passwords (root and `vardr` only);
4. creates the Vardr certificate authority, a server certificate with the given addresses, the agent enrollment CA and the key encrypting MFA secrets;
5. builds the service images and the agent MSI installer with this server's certificate;
6. registers systemd services: `vardr` (the stack starts with the system) and `vardr-restore.timer` (restores requested in the panel);
7. starts the stack, waits for the panel, creates the first administrator account and shows the initial password;
8. finally shows the **backup password** – write it down outside the server, without it the backups cannot be decrypted.

The installer and the server scripts print their messages in English. Each panel account picks its own language (account menu); the language of notifications and NIS2 report drafts is set by the administrator in the panel (*Notifications → System language*, default Polish).

The panel has a certificate from the local Vardr authority: import `/opt/vardr/certs/ca.crt` into the trusted authorities of your browser (the installer shows the SHA-256 fingerprint to compare). Agents are installed from packages downloaded in the panel (*Agents*).

## Upgrade

The same command from a newer bundle: `sudo ./install.sh`. The installer replaces the programs, stack files and rules (the new version in `rules/v<time>`, the last 3 are kept), appends new settings to `.env` and recreates only the changed services. Configuration, certificates and data stay. The server certificate (valid for a year) is renewed when less than 45 days remain.

## SigmaHQ rules

The bundle contains only Vardr's own rules. The open [SigmaHQ](https://github.com/SigmaHQ/sigma) rule library (DRL 1.1 license) is imported on the server with one command – the rules arrive **disabled** and are enabled in the panel (preferably via trial mode):

```bash
sudo /opt/vardr/sigmahq-import.sh
```

Details: [rules.md](rules.md#importing-sigmahq-rules) and the panel: *Detection rules → Import SigmaHQ rules*.

## Firewall

Only the networks that need the server should reach it:

| Port | Who |
|---|---|
| `8443/tcp` (ingest) | networks with computers running the agent |
| `8444/tcp` (panel) | the administrators' and SOC network |
| `3000/tcp` (Grafana) | administrators – or nobody (below) |
| `514/udp+tcp`, `6514/tcp` (collector, 6514 – TLS) | networks of devices sending syslog (plus the collector's `syslog.allow` list) |
| `22/tcp` (SSH) | administrators |

**Docker bypasses ufw and firewalld** – container ports are published by Docker's rules, before the INPUT rules. Traffic to containers is filtered in the `DOCKER-USER` chain, by the port before forwarding (`--ctorigdstport`), e.g. the panel and Grafana only from `10.0.10.0/24`:

```bash
sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8444 --ctdir ORIGINAL ! -s 10.0.10.0/24 -j DROP
sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 3000 --ctdir ORIGINAL ! -s 10.0.10.0/24 -j DROP
sudo apt install iptables-persistent && sudo netfilter-persistent save   # keep after reboot
```

SSH and other services of the server itself – as usual (ufw, firewalld).

**Grafana without network access:** `VARDR_GRAFANA_ADDR=127.0.0.1` in `/opt/vardr/.env`, then `sudo systemctl restart vardr`. Grafana is then reachable only through an SSH tunnel (`ssh -L 3000:127.0.0.1:3000 admin@server`, in the browser `http://localhost:3000`); Grafana links in the panel work while the tunnel is open.

## Archive copy in S3

The NIS2 archive lives on the server disk – the server administrator (or an attacker who takes over the server) can delete it. A copy in S3 storage with **Object Lock in COMPLIANCE mode** cannot be deleted or overwritten until the end of retention – not even by the owner of the storage account. The archiver sends every closed hour (segments, then the manifest) within minutes; each object is locked until the end of the hour + the current retention from the panel. Works with AWS S3 and compatible storage: Wasabi, Backblaze B2, MinIO, Ceph RGW.

1. Create a bucket **with Object Lock enabled** (possible only at creation; it also enables versioning). No default rule is needed – Vardr sets the lock on every object.
2. Create a user (access key) with permissions to that bucket only: `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetBucketObjectLockConfiguration` (no delete).
3. Add to `/opt/vardr/.env` and restart (`sudo systemctl restart vardr`):

```bash
SIEM_ARCHIVE_S3_BUCKET=vardr-archive
SIEM_ARCHIVE_S3_ENDPOINT=https://s3.eu-central-1.amazonaws.com   # MinIO: https://minio.example.local:9000
SIEM_ARCHIVE_S3_REGION=eu-central-1
SIEM_ARCHIVE_S3_ACCESS_KEY=…
SIEM_ARCHIVE_S3_SECRET_KEY=…
#SIEM_ARCHIVE_S3_PREFIX=server1        # several installations in one bucket
#SIEM_ARCHIVE_S3_MODE=GOVERNANCE       # a lock an authorised user can remove (testing)
```

Hours from before the copy was enabled are sent starting with the oldest in retention. A bucket without Object Lock is rejected (nothing is sent). State: *System status → Copy in S3 (Object Lock)*, metrics `siem_archive_offsite_*`, archiver logs (`archive copy`).

Expired objects are removed by a bucket lifecycle rule (e.g. delete noncurrent versions and objects older than retention + 2 days) – the storage will not delete locked ones early anyway. The copy has the same directory layout as the archive: after losing the server, download it into the archive directory of a new installation (e.g. `aws s3 sync`), restore the database from a backup (`restore.sh`) and reconcile the archive in the panel (Urd → inconsistency handling).

## Syslog collector and API connector

Optional stack services (Docker Compose profiles), enrolled with a one-time token without copying it around:

```bash
sudo /opt/vardr/enroll-service.sh collector [agent group]
sudo /opt/vardr/enroll-service.sh connector [agent group]
```

The service is added to `COMPOSE_PROFILES` in `.env` and starts with the stack. The connector then needs the Entra ID application details: `tenant_id` and `client_id` in `connector/connector.yaml`, the secret in `connector/entra.secret`.

## Day-to-day commands

```bash
cd /opt/vardr
sudo docker compose ps              # service state
sudo docker compose logs -f api     # service log
sudo systemctl restart vardr        # restart the stack
sudo ./backup.sh                    # backup now
sudo ./backup.sh password show      # backup password
```

Backups, restores, the archive and recovery on a new server: [operations.md](operations.md).

## Removal

```bash
sudo ./install.sh --uninstall           # services; data and configuration stay
sudo ./install.sh --uninstall --purge   # also the databases, archive and backups (confirm with DELETE)
```

## Building the bundle

On a workstation with Go (Git Bash on Windows or Linux):

```bash
deploy/vardr/build-bundle.sh [version]
```

Result: `dist/vardr-<version>-linux-amd64.tar.gz` and a `.sha256` file. The panel frontend is built with npm; without Node the existing `panel/web/dist` is used (e.g. from `deploy/lab/deploy.sh web`). The installation stack file is `deploy/vardr/docker-compose.yml`; service configuration and backup scripts are shared with the lab stack (`deploy/lab`).
