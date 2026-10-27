# The Hliðskjálf panel

The panel runs at `https://<server>:8444`. The first administrator account is created on the server by the installer, or manually: `docker compose run --rm api bootstrap-admin -username admin` (the initial password is shown once; the panel forces a change at the first sign-in).

## Languages

The panel is available in English and Polish. Each account picks its language in the account menu (*Language*: same as browser, Polski, English) – the choice is stored on the account. Before signing in, the panel follows the browser language.

The **system language** (*Notifications → System language*, panel administrator, recorded in the audit log) decides the language of content the server creates outside the panel: messages on notification channels, descriptions of Grafana health alerts, the default language of NIS2 report drafts, and service messages stored for the panel (backup results, archive verification and inconsistency handling). The default is Polish.

Rules have their title, description and instructions in both languages (`vardr.i18n`, [rules.md](rules.md#vardr-extensions)) – the panel shows them in the account language, notifications in the system language. Validation messages (rules, decoders, settings) are shown in the account language; service logs are in English.

## Permission profiles

Every account has one **permission profile** – a matrix: panel module → access level. Levels within a module are ordered, a higher level includes the lower ones (e.g. rules: read < test < change; archive: read < export < change).

| Module | Levels |
|---|---|
| Alerts | read, handle (status, assignment, notes) |
| Incidents and NIS2 reports | read, handle (creating, alerts, notes, reports to the CSIRT) |
| Events (Mímir) | read |
| Detection rules and MITRE | read, test (test on history, correlation wizard), change (enabling, trials, panel rules) |
| Agents and groups | read, change (groups, deletion, uninstall tokens) |
| Agent deployment | read, change (enrollment tokens, MSI installers) |
| NIS2 archive (Urd) | read, export (auditor packages), change (policy, verification, replay) |
| Syslog decoders | read, test, change |
| Quarantine | read, reprocess |
| Identities | read, change |
| System health | read |
| Notifications | read, change |
| Backups | read, change |
| Users and security | read, change (accounts, profiles, MFA requirement) |
| Audit log | read |

**Built-in profiles** correspond to the former roles and cannot be changed or deleted (they can be copied as a starting point):

| Profile | Can |
|---|---|
| Viewer (`viewer`) | read: agents, events, alerts, rules, archive, decoders, quarantine, identities, system health |
| Analyst (`analyst`) | as the viewer, plus handling alerts and incidents, testing rules and decoders |
| Administrator (`admin`) | everything – including modules added in future versions |

**Custom profiles** are created in *Administration → Permission profiles* (e.g. "NIS2 auditor": archive – export; "Helpdesk": agents – read). A profile with the change right in the "Users and security" module is a **panel administrator** (the "administrators" MFA requirement applies to it). Saving and deleting a profile require the password and are audited; the panel will not allow a change after which no active account would be an administrator, nor deleting a profile with assigned accounts. A profile change takes effect immediately (within 30 s at the latest) – also for signed-in users.

Sensitive operations (disabling a rule, weakening the archive policy, an agent uninstall token, changing a decoder) require re-entering the password and a reason. All changes go to the **audit log**. Sessions expire after inactivity, and an account is temporarily locked after a series of failed sign-ins.

## Incidents and NIS2 reports

An incident (*Detection → Incidents*) combines alerts, findings and actions into one story: severity, status (open → investigating → contained → resolved → closed; changed with buttons for the allowed transitions – work can go back, e.g. from contained to investigating, but **closing is final**: it requires a summary, and a closed incident is read-only, also in the database; a significant incident can be closed only after the final report is submitted), owner, description, impact, root cause, mitigation, indicators of compromise (IoC) and a timeline (notes and every change). Alerts are added from the alert list (select → *To incident*: new or existing) or from the alert details; the incident keeps a **snapshot** of them, so alert retention does not impoverish the documentation.

**Significant incident (NIS2, Article 23 of Directive 2022/2555).** After marking an incident as significant and giving the moment of becoming aware (default – the moment of marking), the panel counts the deadlines of reports to the competent CSIRT:

| Report | Deadline |
|---|---|
| Early warning | 24 h after becoming aware |
| Incident notification | 72 h after becoming aware |
| Intermediate report | on the CSIRT's request |
| Final report | one month after the incident notification |

- For each report the panel prepares a **draft** (in English or Polish – chosen next to the button, by default the system language) from the incident data (description, moment of becoming aware, suspected malicious act, cross-border impact, impact, systems and accounts from alerts, IoC, list of detections, root cause, actions). Fields Vardr does not know (entity name, contact person) are marked "[to complete]".
- The report is sent through the CSIRT's channel (portal, e-mail) – outside Vardr – and marked as **submitted** in the panel (time of submission, case number). The content is frozen, the deadline stops counting, an entry goes to the timeline and the audit log.
- **Reminders** on notification channels with the "incidents" event: marking an incident as significant, 6 h before the 24 h and 72 h deadlines, 3 days before the final report deadline and after a deadline passes (each once).
- **Evidence package**: a button in the incident requests an export from the NIS2 archive (Urd) – full hours from the first to the last alert ±1 h, only the agents from the alerts; requires the "Archive – export" permission, the package waits in *NIS2 archive → Auditor export*. It works in a closed incident too (an entry goes to the timeline), as do copying and downloading reports.

Whether an incident is significant is the organisation's decision (NIS2 criteria and national law) – Vardr does not make it, it only watches the deadlines and keeps the documentation in order.

## Domain sign-in (Active Directory)

AD accounts sign in to the panel with their own username and password (`john.smith`, `COMPANY\john.smith` or `john@company.com`). Settings: *Administration → Domain sign-in*.

1. **Connection** – **LDAPS** only (port 636, with domain controller certificate verification): controller addresses (further ones – fallback), CA certificate (PEM, e.g. of the AD CS authority; empty – system trusted certificates), optionally the name from the certificate (when the address is an IP), a **read-only service account** and the account search base (e.g. `DC=company,DC=com`). The service account password is stored encrypted (key `certs/mfa.key`); the *Check connection* button tests a sign-in with it.
2. **Groups and profiles** – the administrator creates AD groups for the panel in their own OU (any names), enters the OU, and the panel shows the groups; each can be assigned a permission profile. **The order of mappings decides** – an account gets the profile of the first matching group. Groups are recognised by **SID** (renaming a group in AD breaks nothing, a group with the same name elsewhere will not take over access); nested membership counts too (`tokenGroups`).
3. **Account check** – a username without a password: the account's groups and the profile it will get at sign-in.

Behaviour:

- The first sign-in creates the account in the panel (marked "AD" in *Users*); later ones update the username, name and profile. The account is linked by SID – renaming it in AD does not create a second one.
- Membership is checked at sign-in and **every 5 minutes**: an account deleted or disabled in AD or without a mapped group loses its sessions (audit entry), a group change changes the profile immediately.
- A domain account's password is changed in AD (the panel has no "Change password" or password reset for it); the profile follows the groups (it cannot be changed in *Users*). A panel administrator can **disable** a domain account – it then cannot sign in despite the AD group.
- Password re-entry for sensitive operations checks the password in AD. The second factor (TOTP) applies as for local accounts.
- A username taken by a local account – domain sign-in refuses (the administrator renames one of the accounts).
- An empty password is always rejected (in LDAP it would mean an anonymous bind). Testing a connection to a new controller address requires re-entering the service account password – the stored password goes only to stored addresses.
- **The local administrator account remains** as a break-glass account (AD unavailable – domain sign-in reports an error, local accounts work).

## Second sign-in factor (MFA)

After the password the panel asks for a 6-digit code from an authenticator app (TOTP – Microsoft/Google Authenticator, Aegis, 1Password).

- **Who it applies to** is set by the administrator in *Administration → Users*: everyone (default), administrators only or nobody (voluntary). The change requires the password and is audited. When the requirement is enabled, sessions without a second factor are ended, and accounts without an app set it up at the next sign-in (QR code, then a code from the app). An administrator who has no second factor in the current session cannot enable the requirement – the panel will not sign them out halfway through the change.
- **Backup codes**: when enabling, the user gets 10 one-time codes (shown once) for a lost phone. New codes and voluntary disabling – *My account → Account security* (password and code).
- **Lost phone without codes**: the administrator chooses *Reset second factor* on the account (password, audit) – the account sets up the app again. If this concerns the only administrator – on the server: `docker compose run --rm api reset-mfa -username <login>` (audit entry).
- **Protection**: a code works once (the same code will not sign in a second time), clock tolerance ±30 s, 5 wrong codes end the sign-in attempt, and failed codes count towards the account lock. TOTP secrets are encrypted in the database (AES-256-GCM) with a key from `certs/mfa.key` on the server – the installer creates it once; the file is in the backup (`certs/`). Losing the key invalidates the stored apps – accounts must be reset (in the panel or with `reset-mfa`) and set up again.

## Modules

The menu is grouped by the kind of work: **Detection** (Alerts, Incidents, Detection rules, MITRE ATT&CK), **Events** (Search, Identities, Decoders, Quarantine), **Agents** (Agent list, Agent groups, Deployment), **System** (NIS2 archive, System health) and **Administration** (Users, Permission profiles, Domain sign-in, Notifications, Backups, Audit log). The label says what is on the page; the module name from the roadmap is the caption below it.

| Module | Address | What is there |
|---|---|---|
| **Home** | `/` | summary: open alerts, agents, NIS2 archive, system health |
| **Huginn** | `/agents` | agent list: state (online, no contact, stopped without a token, retired – certificate revoked after an uninstall with a token, a separate filter), version, group, buffer, channels; an agent page with the heartbeat, limits, protection state, the tampering log and uninstall tokens; revoking an agent; "Download agent upgrade (MSI)" – the latest installer without a token |
| **Agent groups** | `/groups` | event profile (workstation, server, domain controller), resource limits, protection, the lost-contact alert threshold, notification when an agent is back |
| **Mímir** | `/events` | event search with a histogram; event details with a description and source fields |
| **Identities** | `/identities` | people and their accounts, link suggestions, aliases, organisation domains, shared device accounts, "Check account" |
| **Gjallarhorn** | `/alerts` | alerts with filters (state, level, rule, computer, account, assignee); an alert page: events (timeline), instructions for the analyst, related alerts (computer, account, person ±24 h), notes, assignment, closing with a reason |
| **Risk** | `/risk` | a ranking of people and computers by risk score, the alerts that make up the score, scoring settings ([Risk](#risk-of-people-and-computers)) |
| **MITRE ATT&CK** | `/attack` | the technique coverage matrix (colours: alerts in the period, covered, only disabled rules, none), platform and period filters, technique details with rules, sub-techniques and alerts, layer export for ATT&CK Navigator |
| **Detection rules** | `/rules` | the list of rules from files and built-in rules, content, version history, load errors, enabling and disabling, rule test (also correlation rules) on ClickHouse events, a correlation wizard from sample events (`/rules/correlation`) and rules saved in the panel |
| **Decoders** | `/decoders` | syslog and API decoders in checking order, editing with history, tests on samples or on unrecognised messages, a wizard from samples (marking fields in a message) |
| **Quarantine** | `/quarantine` | unnormalised events grouped by source and reason, originals, a decoder wizard from a group's messages, reprocessing after fixing a decoder |
| **Bifröst** | `/deploy` | enrollment tokens; an MSI installer with the server address and token written in (one file – installation or upgrade with a double-click, GPO/Intune deployment without parameters) and a ZIP package |
| **Urd** | `/archive` | NIS2 archive: state, segments, verifications, inconsistency handling (files unknown to the catalog – adoption after checking hashes or quarantine, with a reason and password; history of operations), policy (enabling, retention, groups), auditor exports, replay to `siem.events_replay` |
| **Himinbjörg** | `/system` | state of services, queues, disks and databases (from Prometheus); links to Grafana: the "pipeline health" and "event overview" dashboards, active alerts, alert rules, Explore – with the chosen time range, and charts of that area at every group and problem |
| **Users** | `/admin/users` | accounts, profiles, password reset, MFA requirement |
| **AI access** | `/admin/ai` | the AI access policy for MCP (tools, data scope, masking), warnings, connecting an AI client, revealing pseudonyms, AI request history ([AI access](#ai-access-mcp-and-data-protection)) |
| **API tokens** | `/admin/api-tokens` | tokens for programs and integrations: profile, validity, last use, revocation; OpenAPI description ([API](#api)) |
| **Audit log** | `/admin/audit` | who changed what and when in the panel |
| **Backups** | `/admin/backup` | tabs: *Settings* (schedule, contents, retention, SFTP/SMB/S3 destination with credentials), backup *History*, *Restore* (list of backups, content check, restoring the database with configuration and/or Grafana with a backup of the current state); on-demand backup, connection test |
| **Notifications** | `/admin/notifications` | channels (Discord, Power Automate / Teams, webhook – [Notifications](#notifications)) with message kinds (alerts with level and rule filters, health, archive anchor), channel test, system language |

## Event search (Mímir)

A query is a list of conditions separated by spaces, combined with AND:

| Syntax | Meaning | Example |
|---|---|---|
| `field:value` | field equal to the value (case-insensitive text) | `user:jsmith code:4625` |
| `field:prefix*` | field starts with | `host:pc0*` |
| `-field:value` | negation | `-action:logged-out` |
| `word`, `"phrase"` | text in the event content (description and raw XML) | `"invoke-expression" powershell` |
| `fields.Name:value` | event source field (the `fields` map) | `fields.TargetUserName:admin` |

Fields: `host` (`computer`), `agent`, `user`, `domain`, `identity` (`osoba`, `person`), `ip` (`src`), `code` (`id`, `eventid`), `action`, `outcome`, `dataset` (`channel`), `provider`, `process`. The list with descriptions is in the panel (help next to the query field, `GET /api/v1/events/fields`).

The time range is picked above the results. Search uses a read-only ClickHouse account with time (30 s) and result limits, so an overly broad query ends with a message, not with server load; narrow the time or add a field.

## Risk of people and computers

*Detection → Risk* (the *Risk of people and computers* permission): a ranking of people and computers by **risk score** – the sum of points for their alerts. Many small alerts, none dangerous on its own, together form a signal (e.g. a few failed logons, unusual PowerShell and a sign-in from a new country by the same person within a week).

- **A person**, not an account: alerts from AD, Entra ID and VPN are joined by the identity (`user.identity`, [Identities](#modules)); without an identity – the account. System accounts (`SYSTEM`, `LOCAL SERVICE`…) and computer accounts (`NAME$`) are not people – their alerts count only for the computer.
- **Points** per alert by level (default: low 1, medium 5, high 15, critical 40; informational 0). An alert counts once, regardless of the number of hits.
- **Decay:** an alert's points halve every 14 days (from the last hit) – an old incident does not hang around forever.
- **A multiplier** (×2 by default) for **privileged accounts** (patterns in the settings, e.g. `*-adm`, `administrator`, `adm.*@example.com` – also without the domain) and **critical computers** (selected agent groups, e.g. domain controllers).
- **Levels:** low, medium (from 20 points), high (from 50), critical (from 100).
- **Alert resolution** when closing: *true positive*, *legitimate activity* (e.g. announced administrator work) or *false positive*. The last two do not count towards risk – resolve the alerts you close so the score reflects reality.
- **An alert when entering the critical level** – the built-in rule "Critical risk of a person or computer" (`vardr-risk-critical`, [built-in rules](rules.md#built-in-rules)); its alerts do not count towards the score.

`siem-detector` calculates the scores every 5 minutes from alerts of the last 8 × the decay period. Clicking a row shows the alerts that make up the score (the largest contributions). A level badge (from medium) is also shown next to the person and computer in an alert and on the agent page. The settings (points, decay, thresholds, multiplier, privileged accounts, critical computers, alert) are changed with the module's *change* permission, with a password and an audit entry.

**GDPR.** Ranking employees by risk is profiling: before using it in a company, agree it with your data protection officer (legal basis, information for employees, retention – scores are rebuilt from alerts, so the alert retention `SIEM_ALERT_RETENTION_DAYS` applies). Grant access only to those who need it – the *Analyst* and *Administrator* profiles can read it, *Viewer* cannot. The score is a pointer for analysis, not an assessment of the person; decisions about an employee require human analysis.

## Working with an alert

1. **Intake.** The alert arrives on a notification channel (Discord) with its level, description and a link.
2. **Investigating.** The analyst opens the alert and assigns it to themselves; the state changes to "acknowledged".
3. **Analysis.** The instructions in the alert say what to check. The event timeline shows the alert's events, and each one links to Mímir. Related alerts show what else happened on the computer, account and for the person.
4. **Notes.** Findings go to notes (the alert timeline).
5. **Closing.** The alert is closed with a reason, e.g. "false positive – vulnerability scanner" or "incident – password changed", and a resolution: true positive, legitimate activity or false positive (the last two do not count towards [risk](#risk-of-people-and-computers)). A bulk action closes many alerts at once.

Lost-contact and silent-source alerts close themselves when the agent or the source comes back. Closed alerts are removed after `SIEM_ALERT_RETENTION_DAYS` (default 365 days).

Further hits of the same rule with the same key (e.g. the same person, the same address) within the merge window go to the same alert: the counter grows and events join the timeline. When one rule raises more than `SIEM_ALERT_NOTIFY_PER_RULE` new alerts within `SIEM_ALERT_NOTIFY_WINDOW`, the channel gets one digest message instead of a series.

## Notifications

*Administration → Notifications*: channels to which Vardr sends messages outside the system – detection alerts (with level and rule filters), incidents and NIS2 report deadlines, health alerts from Grafana and the daily archive anchor. Messages are in the system language. A channel address is a secret: the panel shows only its beginning and end, and disabling a channel, opting out of a message kind, narrowing the filter, changing the address and deleting require a password and are recorded in the audit log.

| Kind | Where | Content |
|---|---|---|
| **Discord** | a Discord channel webhook (`https://discord.com/api/webhooks/…`) | an embed coloured by severity |
| **Power Automate / Teams** | the HTTP trigger of a Power Automate flow (`https://….logic.azure.com/workflows/…` or `https://….api.powerplatform.com/…`) | an Adaptive Card (title coloured by severity, fields, a "Vardr – Panel" button) and data in the `vardr` field |
| **Webhook (JSON)** | any HTTPS address (n8n, ticketing, your own service) | `{source, event, severity, title, text, fields, at}` |

### Microsoft Teams via Power Automate

Microsoft is retiring Teams webhooks based on Office 365 connectors; their successor is *Workflows* (Power Automate) with an HTTP trigger.

1. In Teams, on the channel: *…* → *Workflows* → the template **"Post to a channel when a webhook request is received"** (or a new flow from this template in Power Automate). Choose the team and channel.
2. Copy the trigger address (*When a Teams webhook request is received* → *HTTP URL*). The address contains an access signature (`sig=…`) – whoever knows it can post to the channel; treat it like a password.
3. In the panel: *Add channel* → **Power Automate / Teams**, paste the address, tick the message kinds, save and click *Test*.

The template shows the card from the `attachments` field. A custom flow (e.g. a ticket in the ticketing system, an SMS, escalation only for critical alerts) can use the data in the `vardr` field (the same as the JSON webhook: `event`, `severity`, `title`, `text`, `fields`, `at`). Values from events do not become links in the card (an attacker cannot slip a "Panel" link into a command line).

### Message signing (HMAC)

**Webhook** and **Power Automate / Teams** channels can sign messages (*Sign messages* when adding a channel, or *Enable signing* on the channel). The panel shows the secret (`vardrsig_…`) once; *New secret* invalidates the previous one, and disabling signing or a new secret require a password.

Every message has the headers:

- `X-Vardr-Timestamp` – the sending time (Unix seconds),
- `X-Vardr-Signature` – `sha256=<hex>`: HMAC-SHA256 with the secret over `<X-Vardr-Timestamp>.<request body>`.

The recipient computes the signature from the raw request body, compares it in constant time and rejects messages with a timestamp older than a few minutes (replay protection):

```python
import hashlib, hmac, time

def vardr_signature_ok(secret: str, headers: dict, body: bytes, max_age: int = 300) -> bool:
    ts = headers.get("X-Vardr-Timestamp", "")
    sig = headers.get("X-Vardr-Signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > max_age:
        return False
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, "sha256=" + mac)
```

Power Automate has no built-in HMAC function – for a Teams channel the sender is authenticated by the secret flow address (`sig=…`). The signature is useful when the flow forwards the message to a service that checks it (e.g. an Azure Function), and for webhook channels.

## AI access (MCP) and data protection

*Administration → AI access* (the *AI access (MCP)* permission): connecting an AI model to Vardr through the [Model Context Protocol](https://modelcontextprotocol.io). The model – local (Ollama, LM Studio) or external (Claude Desktop and other MCP clients) – reads events, alerts, rules and system health to assist the analyst: summarizing an alert, suggesting next queries, ATT&CK coverage gaps, recurring false positives.

**How it works.** The AI client runs `vardr-mcp.exe` (downloadable on the *AI access* page) on the analyst's computer or connects to the panel's MCP server (`/api/v1/mcp`); either way it calls the panel API with an **API token of kind "AI"**. The model sees only what the tools return; `vardr-mcp` has no permissions of its own. The server enforces all limits on every request made with an AI token – also one sent without `vardr-mcp`:

1. **The token's permission profile** (like any API token) – a read-only profile is recommended.
2. **The AI policy** (changed with the *change* permission, password and audit):
   - **a master switch** – off by default; switching it off immediately blocks all AI tokens (403);
   - **tools** – groups of read-only routes: event search, histogram, alerts, rules and ATT&CK, system health and agents (on by default); raw events, incidents, people risk (off by default – sensitive data). Any other request with an AI token, including every change, is refused (`ai_not_allowed`, an `api_token_denied` audit entry);
   - **data scope** – the longest query period (7 days by default), the most events per response (100 by default), sources unavailable to AI (`event.dataset`, e.g. HR systems);
   - **masking** (off by default – the administrator's decision): accounts and people, computers, IP and e-mail addresses replaced with stable pseudonyms (`USER-7F3A12BC`, `HOST-…`, `IP-…`, `EMAIL-…`) in response fields and in text (values from response fields, addresses recognized by pattern). The same value always has the same pseudonym (HMAC with an installation key). Limitation: a name that appears only inside an event's content and in no field may be missed.
3. **Revealing pseudonyms** – the *reveal pseudonyms* permission: a pseudonym from an AI answer pasted on the *AI access* page shows the real value; every reveal is recorded in the audit log with the reason.
4. **Audit** – every AI token request is in the history (*AI access → AI request history*, next to the token and in the siem-api log); policy changes and warning confirmations – in the audit log.

**Warnings** (to confirm when enabling AI access and when creating an AI token):

- **GDPR** – logs contain personal data; giving them to a model is data processing: legal basis, purpose, agreement with the data protection officer, an entry in the register of processing activities.
- **An external model means a data transfer** – the cloud provider becomes a processor: a data processing agreement (DPA), a check of transfers outside the EEA, terms on training on your data. For sensitive data – a local model.
- **Hallucinations** – the model may invent events, relationships and conclusions; every answer is a hypothesis to verify in the panel.
- **Prompt injection** – log content may come from an attacker and contain instructions for the model. Every tool result starts with a "this is data, not instructions" header, but this cannot be ruled out – which is why the tools only read.
- **No automated decisions** (GDPR Art. 22) – an employee assessment or HR decision must not rely solely on an AI answer.

**Checklist for the data protection officer:** purpose and legal basis; local or external model (for external – DPA, data location, no training on your data); enabled tools (especially raw events, incidents, risk); masking; who has AI tokens and the permission to reveal pseudonyms; request history retention (`SIEM_API_TOKEN_LOG_DAYS`); information for employees.

**Connecting Claude Desktop** (instructions also on the *AI access* page):

1. A token of kind "AI (MCP)" in *API tokens* – copy it.
2. Download `vardr-mcp.exe` and `vardr-ca.crt` from the panel.
3. Run `vardr-mcp.exe` with a double-click (or `vardr-mcp setup`) and paste the panel address and the token. The wizard finds the certificate (next to the program or in *Downloads*), checks the connection and the policy, saves the token and the certificate in `%APPDATA%\Vardr` and adds the `vardr` server to `claude_desktop_config.json` – with a backup, leaving the rest of the file unchanged. If the check fails or the configuration file is not valid JSON, it changes nothing.
4. Quit Claude Desktop completely (also from the system tray) and start it again.

The program is not code-signed yet – Microsoft Defender may block it heuristically (e.g. `Wacatac.C!ml`). After making sure the file comes from the panel: *Windows Security → Protection history → Actions → Allow on device*; the permission applies to the file in that location.

**Reporting a false positive to Microsoft** (the same applies to `vardr-agent.exe` and `odczytaj.exe`) – after analysis Microsoft removes the detection for everyone, usually within hours to a few days:

1. Make sure the file comes from your Vardr panel (downloaded from it, not from e-mail or another site) – report only such a file.
2. Check the detection name (*Protection history*, e.g. `Trojan:Win32/Wacatac.C!ml`) and the definition version: `Get-MpComputerStatus | Select-Object AntivirusSignatureVersion` in PowerShell.
3. Open [Microsoft's submission form](https://www.microsoft.com/wdsi/filesubmission), choose *Software developer* (or *Home customer*) and sign in with a Microsoft account.
4. Product: *Microsoft Defender Antivirus*; select the file (restore a blocked file from quarantine first or attach it in a ZIP archive); type: *Incorrectly detected as malware/malicious*; enter the detection name and definition version, and in the comment say that it is a component of the Vardr SIEM (open source, AGPL-3.0) and what the program does.
5. The status and verdict appear in the submission history. The verdict *Not malware* means the detection is removed; refresh the definitions on the computer (command prompt as administrator, in `C:\Program Files\Windows Defender`): `MpCmdRun.exe -removedefinitions -dynamicsignature`, then `MpCmdRun.exe -SignatureUpdate`.

The verdict applies to that particular file (its hash) – a new version of the program may need to be reported again until Vardr's programs are code-signed.

**Manual configuration** (other MCP clients): `mcpServers` as a key of the top-level JSON object, next to existing settings:

```json
{
  "mcpServers": {
    "vardr": {
      "command": "C:\\Vardr\\vardr-mcp.exe",
      "env": {
        "VARDR_URL": "https://siem.example.local:8444",
        "VARDR_TOKEN_FILE": "C:\\Vardr\\token.txt",
        "VARDR_CA_FILE": "C:\\Vardr\\vardr-ca.crt"
      }
    }
  }
}
```

`vardr-mcp.exe check` checks the connection, token and policy and lists the available tools ([programs](programs.md#tools)).

**A server with an LLM or another MCP client** (e.g. your own model on vLLM or Ollama with Open WebUI, LibreChat, n8n, VS Code, Cursor): the panel itself is an MCP server – *Streamable HTTP* transport, no `vardr-mcp` to install:

- URL: `https://siem.example.local:8444/api/v1/mcp`, header `Authorization: Bearer vardr_…` (a token of kind "AI (MCP)"; other tokens and panel sessions are refused),
- the client's computer or container must trust `vardr-ca.crt` (Linux: `/usr/local/share/ca-certificates` and `update-ca-certificates`; Node.js: `NODE_EXTRA_CA_CERTS`; Python: `SSL_CERT_FILE`),
- test: `curl --cacert vardr-ca.crt -H "Authorization: Bearer $VARDR_TOKEN" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' https://siem.example.local:8444/api/v1/mcp`.

The server is stateless and only answers (no session, no SSE stream; `GET` – 405). The tools make internal API requests with the same token, so exactly the same applies as for `vardr-mcp`: AI policy, masking, limits, audit of refusals, and every tool call is recorded in the request history. The model must support tool calling (e.g. the Qwen3, Llama 3.1+, Mistral, gpt-oss families) and have a context window of at least 32k tokens; small models more often get arguments wrong and make up conclusions.

### AI assistant in the panel

"**AI analysis**" on the alert page and the "**Ask Vardr**" chat (the ✨ icon in the header) – nothing to install for the analyst. The Vardr server reaches the model through an OpenAI-compatible API (`/v1/chat/completions`): LM Studio, Ollama, vLLM or a cloud service. Settings: *AI access → AI assistant in the panel* (endpoint URL with `/v1`, model, optional API key – never shown; changes need the password and are audited).

- **Permissions** – the assistant works with the logged-in analyst's permissions, narrowed by the AI policy (tools, data scope, masking): the model sees nothing the analyst cannot see and nothing outside the policy. Using it requires the *AI assistant* level in the *AI access* module (the administrator profile has it). The AI policy must be enabled.
- **Read-only, with sources** – the same tools as MCP; every claim in an answer links to data (`[alert:12]`, `[query:…]` – a click opens the alert or the search). Log content is data, not instructions; the model does not judge people (Art. 22 GDPR), it only describes events.
- **Limits** – tool steps per answer (default 6), timeout (300 s), tool result length (12,000 characters – 8,000–16,000 for models with a short context), questions per person per day, concurrent questions (a local model on one GPU: 1–2).
- **Saved with the alert** – the result of "AI analysis" stays in the *AI analysis* card on the alert page (who, when, model; earlier ones selectable). Only people with the *AI assistant* permission (and alert read access) see it – the model's conclusions may rely on data others cannot access; the content is as the model saw it (with masking – pseudonyms). Deleting requires *AI assistant* and alert write access and is audited (`ai_analysis_deleted`). Follow-up questions in the chat are not saved.
- **Incident** – "AI analysis" on the incident page: timeline, scope and impact, IoCs, root cause, recommended actions, open questions; requires the *incidents* group in the AI policy. The analysis includes **proposals for the NIS2 report fields** (description, impact, IoCs, root cause, mitigation): *Insert into the form* moves a proposal into the incident findings (appending to existing text) – the analyst corrects and saves it; saving adds a timeline entry that the findings were completed from AI proposals (analysis number, model). The report draft is built from the incident fields as before – AI neither writes the report nor changes anything without a human.
- **Audit** – every question: an `ai_assistant_used` entry (model, steps, tools, tokens, time, alert); every tool call is in the query history.

**LM Studio** (local test): *Developer* → load a model that supports tools (Qwen3, gpt-oss, Llama 3.1+, Mistral) with a context of at least 16k tokens (32k recommended) → *Settings* → *Serve on Local Network* → *Start Server*. In the panel: URL `http://COMPUTER-ADDRESS:1234/v1` → *Check and load models* → pick the model → save. Windows Firewall must allow connections to port 1234 from the Vardr server.

## API

The panel is a client of its own JSON API (`/api/v1/…`, a session in an `HttpOnly` cookie, CSRF protection with the `X-CSRF-Token` header). Programs – scripts, integrations (SOAR, ticketing, Power Automate), an MCP server – use the same API with an **API token**. Agents have separate routes without a session, authenticated with an enrollment token or certificate: `/enroll/v1/register`, `/enroll/v1/renew`, `/enroll/v1/config`.

### API tokens

A panel administrator creates a token in *Administration → API tokens* (confirmed with a password):

- **A permission profile** like an account – the token sees and changes only what the profile allows. A read-only profile is usually enough for an integration (e.g. *Viewer* or a custom one: alerts and events read-only).
- **Token restrictions regardless of the profile:** it does not manage accounts, profiles or tokens (the *Users and security* module at most read-only), does not perform operations that require a password (weakening the archive policy, restoring backups, changing profiles) or account routes (session, MFA, password change). A stolen token gives no permanent foothold in the panel.
- **Validity** from 1 to 365 days (90 by default) – a token that never expires stays in forgotten scripts. The list shows the last use (time and address) and tokens about to expire; revocation is immediate.
- **The secret is shown once**, at creation; the database keeps only a SHA-256 hash and the beginning of the token (`vardr_abc123…`) to recognize it in the list. The `vardr_` prefix helps secret scanners find tokens committed to repositories.
- **Audit:** every change made with a token is in the audit log as `api:<name>` (with the token number in the details); the "who" fields (alerts, incidents, exports) also show `api:<name>`. A denied request (an operation outside the profile, a session-only route) is an `api_token_denied` entry – an integration error or token misuse.
- **Request history:** every token request (method, path with parameters, response code, response time, IP address) is in the panel – a 24-hour counter next to the token, a click opens the history – and in the siem-api log (`API token request`). The history is kept for 30 days (`SIEM_API_TOKEN_LOG_DAYS`); `429` responses are not recorded.
- **Rate limit:** 600 requests per minute per token (`SIEM_API_TOKEN_RATE`), above it – `429` with `Retry-After`.

Usage – the `Authorization: Bearer` header (no cookie, no CSRF):

```bash
curl -H "Authorization: Bearer vardr_…" "https://siem.example.local:8444/api/v1/alerts?status=open&level=high"
```

```bash
curl -H "Authorization: Bearer vardr_…" "https://siem.example.local:8444/api/v1/events?q=event.code:4625&from=2026-10-26T00:00:00Z"
```

`GET /api/v1/api-tokens/self` returns the token's name, profile, permissions and expiry – to check an integration's configuration.

### API description (OpenAPI)

`GET /api/v1/openapi.json` (no sign-in) returns an OpenAPI 3.1 description of all routes – load it into Swagger UI, Postman or a client generator. The description is built from the same route table as the server (`panel/internal/api/routes.go`), so it never drifts from the code. Each operation lists the required permission (`x-vardr-permission`, e.g. `alerts:read`) and whether tokens may use it (`x-vardr-token`). Query parameters are described for the routes used by integrations (alerts, events, incidents, audit); request and response bodies – as a JSON object.

Errors have a fixed code (`error`), a Polish description (`message`) and – for validation errors – an English one (`message_en`); an integration should recognize an error by its code.
