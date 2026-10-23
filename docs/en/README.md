# Vardr documentation

Vardr is an open-source SIEM: agents and collectors gather events (Windows, syslog, Entra ID), the server normalizes and stores them, detects threats and archives them in line with NIS2, and the Hliðskjálf panel is used for analysis and management.

This English documentation covers installing, operating and extending Vardr. The Polish originals are in [`docs/`](../README.md); the roadmap, project history, lab notes and load tests are available in Polish only.

## Contents

| Document | For whom | What it contains |
|---|---|---|
| [Installation](installation.md) | administrator | server from the bundle: requirements, installation, upgrade, collector and connector, removal |
| [Windows agent](agent.md) | administrator | agent installation (MSI, GPO), protection against stopping, guaranteed delivery, resource limits, audit policy, diagnostics |
| [Panel](panel.md) | analyst, administrator | languages, permissions, incidents and NIS2, domain sign-in, MFA, modules, event search, alert triage |
| [Detection rules](rules.md) | rule author | Sigma format with Vardr extensions, fields, thresholds, correlations, translations, built-in rules, testing, trial mode, SigmaHQ import |
| [Decoders](decoders.md) | decoder author | syslog and API decoders: matching, parsers, field mapping, outcome, time, samples, wizard |
| [Architecture](architecture.md) | everyone | components, event flow, NATS queues, ClickHouse and PostgreSQL tables, detection, archive, security, repository structure |
| [Operations](operations.md) | administrator | server layout, deployment, backups and restore, retention, migrations, monitoring, diagnostics |
| [Programs](programs.md) | administrator, developer | every program: purpose, commands, flags, environment variables, ports, metrics |
| [Development](development.md) | developer | building, tests, CI, conventions, translations, how to add a source, built-in rule or migration |

Changes between versions: [CHANGELOG](../../CHANGELOG.md).

## Names

Modules are named after Norse mythology:

| Name | What it is |
|---|---|
| **Vardr** | the whole system |
| **Hliðskjálf** | the web panel (`siem-api` with the embedded frontend) |
| **Huginn** | the agent list and their state (panel module) |
| **Bifröst** | agent deployment: packages and enrollment tokens |
| **Mímir** | event search |
| **Gjallarhorn** | detection and alerts (`siem-detector`, `gjallarhorn` schema) |
| **Urd** | the NIS2 archive (`siem-archiver`, `urd` schema) |
| **Himinbjörg** | the system health page |
| **Saga** | the PostgreSQL database of the panel, alerts and archive |

## Glossary

- **Agent** – a program on a computer (Windows) or server (syslog collector, API connector) that collects events and sends them in batches over mTLS.
- **Batch** – a portion of events from one agent (contract v1, `internal/contract`).
- **Normalized event** – the common model (`internal/model.Event`): time, computer, account, person, address, action, outcome, source fields.
- **Person (`user.identity`)** – the same human behind accounts in AD, Entra ID and on the VPN.
- **Dataset (`event.dataset`)** – the event source, e.g. `windows.security`, `fortinet.fortigate`, `azure.signinlogs`.
- **Streaming engine** – detection on the NATS stream, event by event.
- **Query engine** – the same rule as a SQL query to ClickHouse, every minute, catching up on what the streaming engine did not see.
- **Correlation** – a rule combining events from many sources or rules (built-in or Sigma correlation).
- **Quarantine** – events that could not be normalized (the original and the reason).
- **System language** – the panel setting deciding the language of notifications, NIS2 drafts and service messages stored for the panel.
