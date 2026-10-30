# Windows agent – Huginn

The `vardr-agent` agent collects events from the Windows logs and sends them to the server over mTLS, with a disk buffer, protection against being stopped and resource limits. Commands, flags and configuration: [programs.md](programs.md). Agent enrollment with tokens and installation packages: [panel.md](panel.md).

## Installing the agent on a computer

1. On the administrator's workstation prepare a package for the computer
   (a certificate with the agent identifier, the CA, the program and the
   default server address):

   ```powershell
   go build -o bin\vardr-agent.exe .\agent\cmd\vardr-agent
   bin\siem-pki.exe package -id agt-pc01 -server 192.168.88.98
   ```

   This creates the `dist\agt-pc01` folder (ignored by git – it contains the private key).

   Usually you do not need this: the panel (*Agents* → Bifröst) issues an MSI installer or a package with an enrollment token.

2. Copy the folder to the computer and in PowerShell or cmd **as administrator**:

   ```powershell
   .\vardr-agent.exe install                       # address from server.txt or a prompt
   .\vardr-agent.exe install -server 10.0.0.5      # address given directly
   .\vardr-agent.exe install -profile dc           # event profile: workstation | server | dc
   ```

   The installer copies the program to `C:\Program Files\SiemAgent`, the
   configuration and certificates to `C:\ProgramData\SiemAgent` (access for
   SYSTEM and Administrators only), checks the connection to the server,
   registers the `SiemAgent` service (automatic start, restart on failure),
   starts it and adds `C:\Program Files\SiemAgent` to PATH.

3. Control (a new window, from any folder):

   | Command | Action | Administrator |
   |---|---|---|
   | `vardr-agent status` | service state; details: server, channels, counters, limits | details – yes |
   | `vardr-agent start` / `restart` | start; restart of the agent inside the service process | yes |
   | `vardr-agent stop [-token T]` | stop (protected agent: token from the panel) | yes |
   | `vardr-agent test` | connection test to the server (TLS + certificates) | yes |
   | `vardr-agent set-server <address>` | change the address, test, restart the agent | yes |
   | `vardr-agent upgrade [-token T]` | upgrade the program (from the folder of the new version) | yes |
   | `vardr-agent uninstall [-token T] [-purge]` | uninstall: service, program and private key (`-purge`: also configuration, buffer and certificates) | yes |

The service runs as LocalSystem (access to the Security channel). Log: `C:\ProgramData\SiemAgent\agent.log`.

**Language.** `vardr-agent` commands print in English or Polish – following the Windows language (to force one: the `VARDR_LANG=en` or `pl` environment variable). Warnings in `status` and in the panel use the same language. The agent log and Event Viewer entries are in English.

### MSI installer (since version 0.6)

`deploy.sh agent` (or the server installer) builds `vardr-agent.msi` on the server (with the `wixl` tool in a container, with this installation's CA).

**A single file to double-click (since 0.7.3).** For a token (Bifröst → "Download installer (MSI)") the panel issues `vardr-agent-<name>.msi` with the server address and token written in: the installer has `SERVER` and `TOKEN` properties with fixed-length placeholders, and the panel replaces them in the file on download (`internal/msipatch` – the MSI structure does not change, the file reads fine with `msiinfo`). A double-click installs and enrolls the agent; on a computer that already has the agent it upgrades it (the token is then skipped). The same file is deployed via GPO, Intune or SCCM without parameters. The file contains the token, so it acts like a token: short validity or an installation limit. For upgrades only, Huginn has "Download agent upgrade (MSI)" – the base installer without a token (it cannot enroll a new computer – the installer reports a missing token). The ZIP package remains an option.

Deployment with parameters (Intune, SCCM, a GPO script), as SYSTEM or administrator – parameters take precedence over values written into the file:

```powershell
msiexec /i vardr-agent.msi /qn SERVER=192.168.88.98 TOKEN=hdt_…   # install and enroll with a token
msiexec /i vardr-agent.msi /qn                                    # upgrade to a newer version (enrollment stays)
msiexec /x vardr-agent.msi /qn UNINSTALL_TOKEN=XXXXX-XXXXX-XXXXX-XXXXX   # uninstall a protected agent
```

The MSI copies the program and the CA to `C:\Program Files\SiemAgent`, then runs `vardr-agent msi-install` (token enrollment and the service – the same path as `install`). A newer version first removes the old one (without data), so an upgrade does not use up a token. An agent installed earlier without MSI is taken over: the MSI stops it, replaces the program and keeps the enrollment. The token does not end up in the installer log. The agent steps: `C:\ProgramData\SiemAgent\msi.log`.

Every agent release needs a new version number (`const version` in `agent/cmd/vardr-agent/version.go`). A rebuilt installer of the same version is installed by `wixl` next to the previous one as a second product (it does not support `AllowSameVersionUpgrades`).

### Automatic updates (since version 0.10)

An agent group has the option *Automatic agent updates* (panel → Agent groups; off by default). Enabling it needs your password and is audited: the panel can then run the installer on every computer of the group – the same trust as in the account that deploys the MSI through GPO.

- The group configuration carries the version, size and SHA-256 sum of the base installer on the server (`agent-dist/vardr-agent.msi` and `AGENT_VERSION` – the server installation bundle or `deploy.sh agent`).
- An agent older than that version waits a random time of up to 30 minutes (downloads spread out), downloads the installer from the panel over mTLS (`/enroll/v1/agent.msi`, only for groups with the option on), checks the size and sum, saves it in the state directory (accessible only to administrators and SYSTEM) and runs `msiexec /i … /qn`. From there it is the same as a manual upgrade: the service comes back in the new version with the same enrollment, and protection reports an installer upgrade (alert when the agent is not back within 15 min).
- Never a downgrade. A failed attempt for a version is retried after 6 hours at the earliest; the error and the path of the `msiexec` log are on the agent page in the panel and in `vardr-agent status`.
- The agent page shows the state: scheduled, installing, failed, updated (from version → to version).
- Agents older than 0.10 lack the feature – the first upgrade to 0.10 is manual (MSI, GPO).
- **Linux agent (since 0.12):** the group configuration also lists the program for each architecture (`agent-dist/vardr-agent-linux-amd64` and `-arm64`, the same version from `AGENT_VERSION`). The agent downloads it from `/enroll/v1/agent-linux/<arch>`, checks the sum and runs it as a transient systemd service (`systemd-run`, outside the agent service's restrictions) with the `apply-update` command. It saves the previous program as `/usr/local/sbin/vardr-agent.previous`, replaces the program and the unit file, restarts the service and waits up to 3 minutes for the new version to confirm its start (and keep running for another 15 s). Without confirmation it restores the previous version, and the error shows in the panel. Log: `/var/lib/vardr-agent/update/update-<version>.log` and `journalctl -u 'vardr-agent-update-*'`. A 0.11 agent is upgraded to 0.12 manually (`sudo ./vardr-agent upgrade`).

### Protection against stopping and uninstalling (since version 0.7)

There is no complete lock: a local administrator can always change the service permissions, and the SYSTEM account can do anything. The goal is to **make it harder and detect it**. Protection is enabled by the agent group (panel → Agent groups → "Agent protection", enabled by default). An agent without configuration from the panel is unprotected.

- **Service permissions.** An administrator can check the service state, start it and restart the agent (`vardr-agent restart` – control code 128 sent to the service). They cannot stop, pause, reconfigure or delete it: `sc stop` and `services.msc` get access denied. They keep the right to change permissions – that is the limit of the protection.
- **Uninstall token.** Panel → Huginn → agent → "Uninstall token": administrator role, a reason and password re-entry, an audit entry. The token is single-use, works only on that computer, by default for 24 h (up to 7 days). The panel shows it once; the database and the computer store only a hash. A new token invalidates the previous one. A command with a token fetches a fresh configuration from the panel itself, so the token works immediately. The panel marks the token as used based on the agent's report.
- **Retirement after uninstall (since 0.7.4).** Uninstalling removes the agent's private key (`certs\agent.key`); configuration and buffer stay (`-purge` removes everything). When the agent reports an uninstall with a token issued in the panel for that computer, the panel revokes its certificates (distributed to ingest as with a manual revocation) and records `agent_retired` in the audit log. In Huginn the agent gets the "retired" state – it disappears from the default list ("Retired" filter), its history stays. Reinstalling on that computer means a new token enrollment and a new identifier (identifiers are never reused – events with one identifier always come from one key).
- **Checks every 30 s.** The agent checks the service permissions, start type and program path, both in the service manager and in the registry. It reports a change and reverts it.
- **Protection events.** A `tamper.jsonl` log in the state directory; the agent sends events from the last 7 days in its heartbeat. An event from the moment of stopping therefore arrives after the next start too. When stopped, the agent immediately sends a last heartbeat with the reason.

| Event | "Agent tampering attempt" alert |
|---|---|
| service stopped without a token (e.g. after `sc sdset` or from the SYSTEM account) | high |
| service permissions or configuration changed (the agent reverted it) | high |
| stop with a "token" the panel did not issue (forged `managed.json`) | high |
| upgrade by the installer after which the agent did not come back within 15 min | high |
| process killed (`taskkill /f`; the service restarts itself after 5 s) | medium |
| `vardr-agent stop` / `uninstall` / `msiexec /x` without a token or with a wrong token | medium |
| stop, upgrade and uninstall with a token; system shutdown | none (entry in the panel) |

`vardr-agent status` and the agent page in the panel show the protection state and recent events. An agent stopped without a token has a red "stopped without a token" badge in the list. The Sigma rule `system_security_service_stopped` now covers only Sysmon: agent stops are reported by a built-in rule that distinguishes a stop with a token.

In an emergency, when the computer cannot reach the panel and a token cannot be used: `sc sdset SiemAgent` restores ordinary permissions, then `sc stop` / `sc delete`. The panel will then raise an alert – that is intended.

## IIS logs (since version 0.10)

On web servers the agent also reads IIS logs in W3C format (the IIS default). Enable it with the group option *IIS logs (web servers)* in the panel (e.g. a "Web servers" group) or in `agent.yaml`:

```yaml
iis:
  enabled: true
  log_dir: 'C:\inetpub\logs\LogFiles'   # default
```

- Every subdirectory of `log_dir` with `u_ex*.log` files (site `W3SVC1`, `W3SVC2`…, FTP too) is a separate agent channel (`iis:W3SVC1`) – shown on the agent page in the panel. A new site is picked up the next time reading starts (group configuration change or service restart).
- The position is saved as for Windows logs: after a break the agent resumes from the next line. A new agent (no saved position) starts with the current day's file, without history.
- Daily and hourly files (`u_exYYMMDD.log`, `u_exYYMMDDHH.log`); the agent moves on to a newer file when the previous one has not changed for 2 minutes. The date and time fields (`date`, `time` – on by default) are required; also recommended: `cs-username`, `cs(User-Agent)`, `sc-status`, `sc-win32-status`.
- On the server the built-in decoder `iis` (dataset `iis.access`) parses the events: client address in `source.ip`, user (Windows/Basic authentication) in `user.name`, outcome `failure` for 401 and 403. The W3C fields keep their own names (`cs-method`, `cs-uri-query`, `sc-status`…), so Sigma rules with `logsource: category: webserver` (or `product: iis`) work unchanged.
- The agent reads the files as SYSTEM; the default IIS directory is readable for it. A missing directory or no W3C files – a warning on the agent page.

## Linux agent (since version 0.11)

The same `vardr-agent` program built for Linux with systemd (amd64, arm64; Ubuntu, Debian, RHEL and derivatives, SUSE). The core is shared with the Windows agent: enrollment with a token from the panel, sending over mTLS, disk buffer, heartbeat (Huginn), certificate renewal and limits from the agent group.

```bash
# in the folder with vardr-agent, ca.crt (from the server, certs/ca.crt) and a token from the panel (Bifröst)
sudo ./vardr-agent install -server 192.168.88.98 -token hdt_…
sudo vardr-agent status
```

- **Files:** program `/usr/local/sbin/vardr-agent`, configuration and certificates `/etc/vardr-agent` (root only, key `0600`), state, buffer and log `/var/lib/vardr-agent`; service `vardr-agent.service` (starts with the system, restarts on failure, file system read-only outside these directories). The service log is also in `journalctl -u vardr-agent`.
- **Commands** as on Windows: `status`, `start`, `stop`, `restart`, `test`, `check`, `set-server`, `run` (console), `enroll` (enrollment without the service), `./vardr-agent upgrade` (from the folder of the new version), `uninstall [-purge]` (the private key is always removed).
- **Source – the systemd journal** (`journalctl -o json`, no extra libraries): by default authentication entries (auth, authpriv – SSH, sudo, su, PAM, logind, account and group changes) and everything with priority *warning* or higher. They reach the server as RFC 5424 syslog (source `syslog:journald`), so the built-in `linux` decoder (`linux.auth`) and the Linux rules work – the same as for servers sending through rsyslog. Additional units or programs in full:

```yaml
journald:
  enabled: true
  units: [nginx.service]     # a whole systemd unit
  identifiers: [cron]        # a whole program (SYSLOG_IDENTIFIER)
  # all: true                # the whole journal (high volume)
```

- The read position is the entry time: after a break the agent resumes from it, without duplicates (the event ID comes from the journal cursor). A new agent starts with current entries (`start_at: oldest` – from the beginning of the journal).
- **Source – Linux Audit (auditd)**: the log `/var/log/audit/audit.log` with rotation. The records of one event (SYSCALL, EXECVE, CWD, PATH… up to EOE) reach the server together (source `file:auditd`) and the built-in decoder `linux-audit` parses them (dataset `linux.audit`, parser `audit`): started programs with arguments (`process-start`, Sigma fields `Image`, `CommandLine`), logins and authentications, sudo, account and group changes, audit configuration changes, SELinux/AppArmor denials and events of audit rules (field `key`). The `user` account is the login account (AUID) – also after sudo. By default the types repeated with every cron job and session are skipped (CRED_*, USER_ACCT, USER_START, USER_END, LOGIN, SERVICE_*, BPF, NETFILTER_CFG); the list: `auditd.exclude`. Without auditd the agent waits for the file (the channel without an error). Recommended audit rules with the `vardr_*` keys for the detection rules (`rules/linux/linux_audit_*`):

```bash
sudo apt install auditd          # or: sudo dnf install audit
vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules
sudo augenrules --load
```

```yaml
auditd:
  enabled: true                  # agent installed with 0.11.0 before 1.8.1 – add it by hand
  # exclude: [CRED_ACQ, …]       # [] – no skipping
```

  Sigma rules: `logsource: {product: linux, service: auditd}` or `{product: linux, category: process_creation}`.
- **Limits from the group:** priority as the unit's CPU and I/O weight, CPU limit and hard memory limit in the service cgroup (`systemctl set-property --runtime`, changed without a restart), soft memory limit, EPS and bandwidth as on Windows. The group profile (Event Log channels) does not apply to the Linux agent.
- Without root (`vardr-agent run` as an ordinary user, e.g. in a test) the agent reads only what `journalctl` shows it – a user in the `adm` or `systemd-journal` group sees the system journal.
- **Protection** (enabled in the agent group, as on Windows): the agent writes the drop-in `/etc/systemd/system/vardr-agent.service.d/50-vardr-protect.conf` with `RefuseManualStop=yes` – `systemctl stop` and `restart` refuse. Stopping, upgrading and uninstalling only with a one-time token from the panel: `sudo vardr-agent stop -token …`, `sudo ./vardr-agent upgrade -token …`, `sudo vardr-agent uninstall -token …`; `sudo vardr-agent restart` works without a token (restart inside the process, SIGHUP). The protection journal (alert in the panel) records: a command without a valid token, SIGTERM sent bypassing systemd (`kill`, `systemctl kill` – ignored, the agent keeps running), killing the process (SIGKILL – systemd starts the agent again after 10 s and it reports the kill), a stop bypassing the token (e.g. `systemctl isolate`), removing the protection drop-in (restored), changing or removing the service file (restored), disabling start with the system (`systemctl disable` – enabled again), masking and foreign drop-ins of the service (reported). A system shutdown is not an alarm. Root can bypass the protection (e.g. by changing the service and stopping it right away) – the goal is to make it harder and detect it, and the panel reports the gap in heartbeats anyway.
- **Source – log files** (`files:`): any text files, line by line, with rotation by rename (logrotate) and by truncation (copytruncate). A line reaches the server as syslog with the agent's host name and the program name `app` (source `syslog:file`, channel `file:<path>`), so it is parsed by a decoder matched on `app` – the same as for messages from rsyslog (the decoder wizard in the panel); without a decoder the event has the `syslog.generic` dataset. The event time is the moment of reading unless the decoder takes the time from the content. The agent checks patterns (`*.log`) every 30 s – a new matching file (e.g. a log with a date in its name) is read right away from the beginning, without a restart (since 0.12). The first run reads from the end of the file (`start_at: oldest` – from the beginning). The service has its own `/tmp` (`PrivateTmp`) – files in `/tmp` are not visible to it.

```yaml
files:
  - path: /var/log/nginx/*.log
    app: nginx
  - path: /opt/app/logs/app.log   # app by default: the file name without extension
```

- **Package from the panel:** for a token Bifröst issues `vardr-agent-<name>-linux-<amd64|arm64>.tar.gz` – the program, `ca.crt`, `server.txt`, `token.txt` (0600) and `install.sh`. On the server: `tar xzf …`, `cd vardr-agent-<name>/`, `sudo ./install.sh` (address and token from the files next to it). Programs for both architectures are built into `agent-dist/` (`deploy.sh agent`, `vardr-agent-linux-amd64`, `vardr-agent-linux-arm64`).
- **Automatic updates** (since 0.12) – as in Windows, see [Automatic updates](#automatic-updates-since-version-010).

## Resilience to state removal

Read positions are saved in `<state_dir>\state.json` and (every 30 s) in a copy
in the registry `HKLM\SOFTWARE\SiemAgent\Instances\<id>` (an agent in the console
without privileges: `HKCU`). The copy is also a marker that the agent has run before:

| Situation | Behaviour |
|---|---|
| first run | reading according to `start_at` |
| deleted / damaged `state.json` | positions from the registry copy – possible duplicates, no gaps |
| file and positions in the copy deleted (marker remains) | reading from the oldest events in the log |
| file or directory deleted while running | recreated from memory within ~2 s |

Each of these cases is reported as an error (log, Event Viewer, `status`).
If an administrator deletes both the file and the whole registry key, it looks
like a first run to the agent – that is detected only by the server (heartbeat).
Uninstalling the service does not remove the registry key.

## How guaranteed delivery works

1. The reader subscribes to an Event Log channel from the saved bookmark (`EvtSubscribe`).
2. Events (raw XML) are batched: 500 events / 4 MiB / 2 s.
3. The batch goes over TLS 1.3 with a client certificate; `agent_id` = the certificate CN.
4. **The channel position is saved only after the `accepted` response.**
   A failure at any moment means at most a resend (the server deduplicates
   by `id`), never a gap.
5. When the server is unavailable, sending is retried with a growing delay,
   readers pause, and unsent events wait in the disk buffer or the Windows log.
6. A drop in the record number (cleared log) increments the generation in `id`.

Verified: 40,123 / 40,123 System + Application events after hard-killing the
agent, 30% of 503 rejections and switching the server off – nothing missing.

## Diagnostics

```powershell
vardr-agent status
```

Shows the state of the service, the server connection (last accepted batch, last
error), each channel (OK / NO CHANNEL / ACCESS DENIED / ERROR, last record,
lag), counters, limits, throttling and resource use. The data comes from
`<state_dir>\status.json`, refreshed every 5 s; a record older than 30 s is
marked as outdated (agent stopped or hung).

In service mode warnings and errors also go to the Event Viewer
(Application log, source `SiemAgent`, ID 2000 = warning, 3000 = error,
1000 = start/stop), with repeats suppressed for 10 minutes.
The `<state_dir>\agent.log` file is rotated while running (`logging`).

## Security of the agent files

`0600` permissions do not work on Windows – files inherit the folder ACL,
and in `C:\ProgramData` ordinary users have read access. An agent running
as SYSTEM / administrator sets, at every start (and the service installer does too),
a protected access list on the state directory and the private key: SYSTEM
and Administrators only. `vardr-agent check` shows whether the key and the state
directory are protected. Run without administrator rights, the agent does not
narrow the ACL (it would lock itself out) and reports this in its status.

## Resource use and limits ("the muzzle")

The `limits` section in `agent.yaml` (example in `agent/configs/agent.example.yaml`)
or the agent group in the panel: process priority, a hard CPU limit (Windows Job Object),
a soft Go heap limit and a hard process memory limit, limits of events per second and bandwidth.
Limits do not lose data – the excess waits in the Windows log, and the agent logs
the warning "the agent cannot keep up with the log" when the read lag exceeds 5 minutes.

Measurements (Ryzen 5 7500F, 12 threads; reading ~40k System + Application events,
1.4 KB on average; every variant received all events):

| Variant | Read time | Notes |
|---|---|---|
| no limits | ~1.1 s | ~23 µs of CPU per event; idle ~0% CPU |
| default (below_normal, 150/400 MB) | ~1.1 s | |
| `cpu_max_percent: 5` | ~1.8 s | on average ≤ 5% of the computer; short spikes within the Windows window |
| `cpu_max_percent: 1` | ~8.6 s | on average ≤ 1% of the computer |
| `max_eps: 5000` | ~6.7 s | as expected (~7 s) |
| `max_send_kbps: 500` | ~16 s | |
| `priority: background`, CPU loaded at 100% | ~13 s | the agent waits until the computer is free |
| `priority: normal`, CPU loaded at 100% | ~7 s | the agent's impact on the loading program ~1% |

Memory: working set ~22–26 MB, private bytes ~55–59 MB. The Go heap is only
2–7 MB – the rest is the Go runtime and Windows libraries, so the soft memory
limit is a safeguard against unusually large events, not a way to lower the
base usage.

Since version 0.2.0 the default is `max_procs: 2`: threads 22 → 11, handles ~310 → 218,
CPU time under full computer load 4.3 s → 3.3 s; reading a backlog
without load ~1.4 s instead of ~1.1 s.

## Audit policy

**Ready-made script:** [deploy/windows/vardr-gpo.ps1](../../deploy/windows/vardr-gpo.ps1) – run on a domain controller (domain administrator) it creates and links the GPO "Vardr - polityka audytu" (the whole domain: advanced audit policy, command line in 4688, PowerShell script block logging, a 256 MB Security log) and "Vardr - dzienniki DC" (1 GB Security on domain controllers). The GPO names are fixed identifiers (in Polish). It can be run repeatedly. Verified in the lab (Windows Server 2025, Windows 11): failed logons (4625, 4776, 4768), account and group changes (4720, 4732, 4733, 4726), processes with a command line (4688) and PowerShell (4104) reach Mímir.

**Sysmon:** [deploy/windows/sysmon.ps1](../../deploy/windows/sysmon.ps1) installs or upgrades Sysmon (a program signed by Microsoft, configuration by default SwiftOnSecurity or from a share `-Source \\domain\NETLOGON\sysmon`). It suits a computer startup script in GPO and can be run repeatedly. The agent (since 0.6.2) installs nothing – it reports the Sysmon state (version, configuration hash), and in an agent group with the "Sysmon required" option the panel reports computers without Sysmon, with Sysmon stopped or with a configuration different from most of the group.

The agent collects only what Windows records. The minimum in GPO
(*Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration*):

- Logon/Logoff: Logon, Logoff, Special Logon, Account Lockout – Success/Failure
- Account Logon: Credential Validation, Kerberos Authentication Service,
  Kerberos Service Ticket Operations – Success/Failure (DC)
- Account Management: User Account Management, Security Group Management – Success/Failure
- Detailed Tracking: Process Creation – Success
  + *Administrative Templates → System → Audit Process Creation →
  Include command line in process creation events* = Enabled
- Policy Change: Audit Policy Change – Success
- System: Security System Extension – Success
- PowerShell: *Turn on PowerShell Script Block Logging* = Enabled
- Sysmon: installation with a base configuration (separately)

## Agent disk buffer (since version 0.6)

A batch that could not be sent immediately (no network, server overloaded) goes to `C:\ProgramData\SiemAgent\buffer` (written with `fsync`), and the agent saves the read position and reads on. A separate thread sends batches from disk, oldest first. A long connection outage therefore no longer depends on the Windows log size.

- **Limit:** 1024 MB by default (`buffer.max_mb` in `agent.yaml` or "Disk buffer" in the agent group in the panel; 0 = disabled). The buffer never takes the last 1 GB of free space (`buffer.min_free_mb`).
- **When full** (`buffer.on_full` or the group in the panel): `pause` (default) – new events wait in the Windows log as without a buffer; `drop_oldest` – the oldest batches in the buffer are removed, and the number of lost events goes to the status and the panel.
- The buffer state is shown by `vardr-agent status` and in the panel (Huginn → agent). The panel reports a problem when batches wait longer than 5 minutes, when the buffer is full and when something was lost.

**Clock:** with every heartbeat the agent measures its clock offset from the server (the `X-Vardr-Time` header) and every 5 minutes checks the Windows Time service (W32Time). The panel reports an offset over 60 s and a disabled time service (stopped is normal outside a domain – Windows starts it on demand).

## Windows log sizes

Without the disk buffer (disabled, or full in `pause` mode) the Windows log is the buffer. When the server is unavailable, unsent events wait in the log, and once it is full Windows overwrites the oldest. The default 20 MB at typical traffic gives:

- on a workstation: a few hours of margin;
- on a busy server or domain controller: from a dozen seconds to a few minutes.

Recommended sizes (GPO: *Computer Configuration → Policies → Administrative Templates → Windows Components → Event Log Service → <log> → Specify the maximum log file size (KB)*, keeping overwriting of the oldest entries):

| Log | Workstations | Servers | Domain controllers |
|---|---|---|---|
| Security | 128–256 MB | 512 MB–1 GB | 1–4 GB |
| System, Application | 64 MB | 128 MB | 128 MB |
| PowerShell/Operational, Sysmon | 64 MB | 256 MB | 256 MB |

Once on a single machine (administrator): `wevtutil sl Security /ms:1073741824`.

The agent watches this itself:

- **every minute** it checks what part of the log is taken by events not sent yet. From 50% it reports a warning, from 80% an alarm, both with the estimated time until overwriting at the current rate;
- **on resume** (e.g. after a long shutdown) and while running it reports the exact range of records overwritten before reading ("DATA GAP");
- **at start** it suggests enlarging a Security log smaller than 128 MB and warns about the "do not overwrite" setting, with which Windows stops recording new events once the log is full.

All these messages go to the agent log, to `vardr-agent status` and (when the agent runs as a service) to the Event Viewer (Application, source `SiemAgent`).
