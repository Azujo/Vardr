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

Ports: `8443/tcp` (agents), `8444/tcp` (panel), `3000/tcp` (Grafana), optionally `514/udp+tcp` (syslog collector).

## Installation

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
