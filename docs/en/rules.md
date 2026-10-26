# Detection rules

Rules are YAML files in the [Sigma](https://sigmahq.io/docs/basics/rules.html) format with Vardr extensions (the `vardr` key). They live in the repository in `rules/` (`windows/`, `network/`, `cross/`, `correlation/`) and are deployed to the server. One rule runs in both engines: **streaming** (every event from the queue, an alert within seconds) and **query** (the same rule as SQL on ClickHouse every minute – it catches up after outages, late events and memory limits). Code: `internal/detect` (loading, compiling, evaluating, SQL), `server/internal/detector` (engines, thresholds).

Vardr's own rules are written in Polish with an English translation (`vardr.i18n.en`); the panel shows the language of the account.

## Example

```yaml
title: Seria nieudanych logowań na jedno konto (brute force)
id: 2feca112-9567-41b7-83de-92c2516f6cdc
status: stable
description: |
  Co najmniej 10 nieudanych logowań (4625) na to samo konto w ciągu 5 minut.
author: Vardr
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  computer_account:
    TargetUserName|endswith: '$'
  empty:
    TargetUserName: ['', '-']
  condition: selection and not computer_account and not empty
falsepositives:
  - Program z zapamiętanym starym hasłem
level: medium
vardr:
  group_by: [TargetUserName]
  threshold:
    count: 10
    window: 5m
  suppress: 1h
  instructions: |
    {{count}} nieudanych logowań na konto {{TargetDomainName}}\{{TargetUserName}}
    w {{window}}. Sprawdź, skąd były próby …
  i18n:
    en:
      title: "Series of failed logons to one account (brute force)"
      description: |
        At least 10 failed logons (4625) to the same account within 5 minutes.
      instructions: |
        {{count}} failed logons to account {{TargetDomainName}}\{{TargetUserName}}
        in {{window}}. Check where the attempts came from …
```

Your own rules may of course be written directly in English – the base texts (`title`, `description`, `vardr.instructions`) are shown whenever there is no translation for the account language.

## Header fields

| Field | Required | Meaning |
|---|---|---|
| `title` | yes | alert title |
| `id` | yes | a stable identifier (UUID); changing `id` makes a new rule (history and panel settings stay with the old one) |
| `level` | yes | `informational`, `low`, `medium`, `high`, `critical` – the alert level and the notification channel filter |
| `logsource` | yes | the source (below) |
| `detection` | yes | selections and the condition |
| `status`, `description`, `author`, `references`, `tags`, `falsepositives`, `date`, `modified` | no | description in the panel; ATT&CK `tags` – below |

### MITRE ATT&CK tags

Tags in the Sigma convention: technique `attack.t1110.001`, tactic `attack.credential_access`; groups and software (`attack.g0016`, `attack.s0002`) are allowed but do not go into the matrix. Every rule that creates alerts should have at least one technique (a correlation base rule does not have to; the correlation has the technique).

- **Dictionary**: ATT&CK Enterprise built into Vardr (`internal/attack/enterprise.json`, currently version 20). Since version 20 the Defense Evasion tactic is split into `stealth` and `defense_impairment`, and some techniques moved (e.g. clearing logs: T1070.001 → T1685.005, disabling security tools: T1562.001 → T1685).
- **Checking**: `siem-detector check` prints `WARN` for an unknown technique, a deprecated technique (with its successor) and a non-existent tactic; the rule still works. The rule test in the panel shows the same warnings (in the account language), and the `TestRulesAttackTags` test guards the repository and built-in rules.
- **No fixed technique**: antivirus detections (Defender, ASR) concern different techniques depending on the threat – such rules have the `vardr.attack_dynamic` tag instead of `attack.t…` (the coverage test does not require them).
- **Tactics**: a technique points to its own tactics (matrix columns), so a tactic tag is optional – it only helps reading the rule.
- **In the panel**: technique badges with rules and alerts (with a link to attack.mitre.org), alert filters by technique (`/alerts?technique=T1110` – with sub-techniques) and tactic, the coverage matrix (*Detection → MITRE ATT&CK*) with a layer export for ATT&CK Navigator, the technique in alert notifications. The correlation wizard adds to the correlation the `attack.*` tags of the rules it was built from.
- **Updating the dictionary** (a new ATT&CK version, usually twice a year): download `enterprise-attack.json` from `github.com/mitre-attack/attack-stix-data` and run `go run ./tools/cmd/attackgen enterprise-attack.json > internal/attack/enterprise.json`, then `siem-detector check rules`.

## logsource

| `product` | `service` / `category` | Events |
|---|---|---|
| `windows` | `security`, `system`, `application`, `sysmon`, `powershell`, `windefend`, `taskscheduler` | Windows log channel |
| `windows` | `category: process_creation` | Sysmon 1 or Security 4688 |
| `windows` | `category: ps_script` | PowerShell 4104 |
| `windows` | `category: network_connection`, `file_event`, `dns_query`, `registry_set` | Sysmon 3, 11, 22, 13 |
| `fortigate` (`fortinet`) | – | `fortinet.fortigate` (syslog decoder) |
| `mikrotik` (`routeros`) | – | `mikrotik.routeros` |
| `azure` (`entra`) | `signinlogs`, `auditlogs` | Entra ID logs from the connector |

Other values are rejected at load time. A rule without `service`/`category` covers the whole product (e.g. all Windows events).

## detection

A **selection** is a `field: value` map. All fields must match (AND). A list of values means any of them (OR). A list of maps means any of the maps. A list of words (without fields) means keywords searched in the event content (description and original XML).

**Values:** text compared case-insensitively, `*` and `?` as wildcards, numbers, `null` (the field does not exist or is empty).

**Modifiers** (`Field|modifier`):

| Modifier | Meaning |
|---|---|
| (none) | equal (with `*`, `?` wildcards) |
| `contains`, `startswith`, `endswith` | contains, starts with, ends with |
| `re` | RE2 regular expression (case-sensitive unless `(?i)`) |
| `cidr` | address in a network, e.g. `IpAddress|cidr: ['10.0.0.0/8', '192.168.0.0/16']` |
| `all` | with a list: all values must match (e.g. `CommandLine|contains|all: ['-enc', 'hidden']`) |
| `exists` | `true` – the field exists, `false` – it does not |

**Condition** (`condition`): selection names with `and`, `or`, `not` and parentheses, plus `1 of selection_*`, `all of selection_*`, `1 of them`, `all of them`. A single text condition (no list of conditions).

Not supported and explicitly rejected (a rule does not work "partly"): Sigma aggregations (`| count() by …`), `timeframe`, `near`, the `base64offset`, `windash`, `wide` modifiers etc. Thresholds are expressed with `vardr.threshold`.

## Event fields

A rule can use three kinds of names.

**Sigma and Windows names:** `EventID`, `Channel`, `Provider_Name`, `Computer` and `EventData` fields (e.g. `TargetUserName`, `IpAddress`, `LogonType`, `CommandLine`, `Image`, `ScriptBlockText`). Some fields have aliases across sources, e.g. `Image` is also `NewProcessName` from 4688, and `SourceIp` is also `IpAddress` (list: `internal/detect/event.go`, `aliases`).

**Common names (ECS):**

| Field | Column | Description |
|---|---|---|
| `event.code` | `event_code` | Event ID |
| `event.dataset` | `event_dataset` | source, e.g. `windows.security` |
| `event.action`, `event.outcome` | `event_action`, `event_outcome` | action, outcome (`success`/`failure`) |
| `event.provider` | `event_provider` | provider |
| `host.name` | `host_name` | computer or device |
| `user.name`, `user.domain` | `user_name`, `user_domain` | account |
| `user.identity` | `user_identity` | person (the same account in AD, Entra, on the VPN) |
| `source.ip` | `source_ip` | source address |
| `process.name`, `process.command_line` | | process |
| `agent.id`, `message` | | agent, event description |

**Source fields** from decoders: any keys of the `fields` map, e.g. `fortinet.action`, `azure.app`, `source.geo.country_iso_code`. Mímir shows the field set of a given source (event details).

A field that is not in the event matches no value, except `null` and `exists: false`.

## Vardr extensions

```yaml
vardr:
  mode: both            # stream | index_query | both (default both)
  group_by: [TargetUserName]
  suppress: 1h
  threshold:
    count: 10
    window: 5m
    distinct: TargetUserName   # optional: number of distinct values instead of events
  instructions: |
    …
  enabled: true
  i18n:                 # translations (optional)
    en:
      title: Series of failed logons to one account
      description: |
        …
      instructions: |
        …
```

| Key | Meaning |
|---|---|
| `mode` | engine: `stream` (streaming only), `index_query` (queries only – e.g. expensive rules or on late data), `both` |
| `group_by` | alert key fields. Hits with the same key within the `suppress` window merge into one alert (the counter grows). Without `group_by` every event is a separate alert. |
| `suppress` | the merge window, 1h by default with `group_by` |
| `threshold.count`, `window` | an alert only at `count` (2–10,000) matching events with the same key in any `window` (10s–24h) measured by event time. All events of the series go into the alert, then further ones until the end of `suppress`. |
| `threshold.distinct` | instead of the number of events – the number of distinct values of a field (e.g. password spraying: 5 different accounts from one address). The same attempt seen in two logs does not inflate the result. |
| `instructions` | what the analyst should do; shown in the alert and in the notification |
| `enabled` | `false` disables the rule without deleting the file (the panel can override it) |
| `i18n` | title, description and instructions in other languages (supported: `en`). The panel shows them to accounts with that language, notifications – when it is the system language (Notifications → *System language*). No translation – the base text. The translated instructions use the same `{{…}}` variables. Alerts store the texts in both languages when they are created. |

**Variables in `instructions`:** `{{Field}}` – the value of a field from the (first) event, e.g. `{{TargetUserName}}`, `{{IpAddress}}`, `{{host.name}}`; a missing value gives "(brak)". Threshold rules additionally have `{{count}}` (number of events or values), `{{window}}` (the window) and `{{values}}` (the list of values with `distinct`).

## Correlation rules

A correlation rule combines the hits of several rules (or many hits of one) into one alert. The format is [Sigma Correlation](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md). Base rules and the correlation can be in one file (YAML documents separated by `---`) or in separate files. A correlation points to base rules by `id` or `name`.

```yaml
title: New account immediately added to a privileged group
id: fc22af54-b46e-449d-a6fd-e100cffa9153
level: critical
correlation:
  type: temporal_ordered
  rules:
    - 9f379649-a04b-43de-b3a0-25587cf713de # User account created (4720)
    - f406b909-37ba-4b21-b8c2-f4bd5cbf3192 # Added to a privileged group
  group-by: [account]
  timespan: 1h
  aliases:
    account:
      9f379649-a04b-43de-b3a0-25587cf713de: TargetSid
      f406b909-37ba-4b21-b8c2-f4bd5cbf3192: MemberSid
  generate: true
vardr:
  instructions: Account {{key}} was created and added to group {{TargetUserName}} within {{window}}.
```

| Type | When an alert | `condition` |
|---|---|---|
| `event_count` | at least N base rule hits in the window | `gte: N` (or `gt: N-1`) |
| `value_count` | at least N distinct values of a field in the window | `gte: N`, `field: <field>` |
| `temporal` | all base rules hit in the window, in any order | – |
| `temporal_ordered` | all base rules hit in the window, in the order of `rules` | – |

- **`group-by`** – events are joined only for the same field values (e.g. the same account). Without `group-by` all events count together.
- **`aliases`** – when the same "thing" has a different field in each base rule (the SID of a new account is `TargetSid` in 4720 and `MemberSid` when added to a group). The alias is a name in `group-by`, and under it base rule (`id` or `name`) → field.
- **`timespan`** – a window from `1m` to `24h` (units `s`, `m`, `h`, `d`).
- **`generate`** – `false` (default): base rules do not create alerts themselves (the panel describes them as "correlation base rule"). `true`: base rules still alert, the correlation is an additional alert at a higher level.
- **`vardr`** – in a correlation rule only `enabled`, `suppress` (default the larger of 1 h and `timespan`), `instructions` and `i18n`. Besides the fields of the last event, the instructions have `{{count}}` (number of events), `{{window}}`, `{{rules}}` (titles of the rules that hit) and `{{key}}` (the `group-by` values).

**How it works.** Every minute (together with the built-in correlations) the detector looks in `siem.events` for keys from newly ingested events of base rules. For those keys it fetches events from the `timespan` window back (plus an hour for late events) and checks the condition. The alert gets the `correlation` engine and contains all events that satisfied the correlation. Repeated runs do not duplicate events (a rule–event pair is in an alert once), and further hits of the same key within the `suppress` window join the open alert.

**Limitations.** No `lt`, `lte`, `eq`, `neq` conditions (an alert on "too few" events makes no sense when evaluating new events) and no `value_sum`/`value_avg` types. A base rule cannot have a threshold (`vardr.threshold`) – the correlation itself expresses the threshold. At most 50,000 events of one correlation per run; beyond the limit the run ends with an error in the detector log – narrow the base rules or shorten the window. The built-in correlations ("success after failures", "new country") stay in code, because they need history outside the window.

### Correlation wizard in the panel

*Detection rules → New correlation (wizard)* (`analyst` role; saving – `admin`) builds a correlation rule from sample events:

1. **Events.** Up to 10 samples – from the search in the wizard or from Mímir (event details → "Add to correlation wizard"). The list lives in this browser tab.
2. **Steps.** For each event the wizard shows the deployed rules that match it (threshold rules cannot be a base), or proposes a new base rule from the selected fields (by default the event kind: `EventID`, and for devices `event.action` and `event.outcome`). Events with the same choice are one step; the order of steps follows the time of the samples.
3. **Condition.** The key is a value present in all steps (e.g. the SID of a new account as `TargetSid` in 4720 and `MemberSid` in 4728 – the wizard adds `aliases` itself). With one step: a value common to all samples, and for `value_count` a field whose values differ. The type and window are suggested (window ≈ twice the gap between samples).
4. **Description and test.** Title, level, description, instructions, `generate` (when the correlation uses deployed rules, the wizard by default keeps their alerts). The generated YAML can be edited by hand and tested on history like any rule.

**Panel rules** are stored in Saga (`gjallarhorn.panel_rules`), and the detector loads them next to the `rules/` directory as the file `panel/<correlation id>.yml` (within 30 s, without a deployment). They have a version history, enabling and disabling like file rules; an administrator can edit (YAML) and delete them (reason and password, audit). Panel rule ids cannot repeat ids of deployed rules – in a conflict the repository file wins. A good rule is worth moving to the repository (`rules/correlation/`) and deleting from the panel.

**Fields with a space in the name** (Microsoft Defender: `Threat Name`, `Severity Name`, `Process Name`, `Detection User`, `New Value`…) are written in selections with or without quotes (`Threat Name|contains: Mimikatz`), the same in `group_by` and instructions (`{{Threat Name}}`). Defender events have the `windows.defender` dataset (logsource `service: windefend`); the agent collects them since version 0.7.2.

## Good practice

- **Group by what the analyst will block or check:** account (brute force), address (spraying), person (`user.identity` – attempts from many sources), computer (suspicious processes).
- **Exclusions as separate selections** (`computer_account`, `empty`, `local`) in an `and not …` condition, described in `falsepositives`.
- **Concrete instructions:** what to check, how to tell a false positive, what to do in a real incident.
- **Level by impact:** `critical` only for near-certain events (e.g. a cleared Security log), `high` – needs a reaction within hours, `medium` – to review, `low` – context.
- **A rule across sources** (e.g. sign-ins in AD, Entra and on the VPN) uses common fields (`event.outcome`, `user.identity`, `source.ip`) and a condition on `event.dataset`. Example: `rules/cross/password_spraying_multi_source.yml`.
- **Do not change `id`** when fixing a rule – the version history and panel settings are tied to `id`.

## Testing

1. **Locally:** `go run ./server/cmd/siem-detector check rules` loads all rules and prints errors (`ERROR`; exit code 1).
2. **In the panel** (*Detection rules → Rule test*, `analyst` role): the pasted rule runs on ClickHouse events from the last 1–168 hours. You see the hits, and for threshold rules – the alerts that would be created. A correlation rule is tested the same way: the pasted text can also contain base rules (documents after `---`), missing ones are taken from the loaded rules; the result is alerts with the key and events. The test uses the same limits as the search.
3. **Engine compatibility test** (`server/internal/detector/compat_test.go`): an event corpus (`testdata/`) goes through both engines, and the test checks that every rule from `rules/` gives the same hits in streaming and in SQL. A new rule should have an event in the corpus that triggers it. How to run: [development.md](development.md#tests).
4. **Translations:** `TestOwnRulesTranslated` checks that every own rule has an English title, description and instructions with the same `{{…}}` variables.
5. **In the lab:** trigger an event on a real source (e.g. failed logons to a DC, `fortisim -scenario vpn-brute`, `curl … entrasim/sim/scenario?name=spray`) and check the alert in Gjallarhorn.

## Deployment

```bash
deploy/lab/deploy.sh rules
```

The script first checks the rules (`siem-detector check`). Then it copies them to the server into a new directory `rules/v<time>` and atomically switches the `rules/current` link. The detector loads the changes within 30 s without a restart. A rule with an error does not stop the others: it is skipped, and the error is visible in the panel and in the Grafana alert "Detection rules with errors". Every change of a rule's content is a new version in the history (panel → rule → Versions). On a server installed from the bundle, the rules are upgraded together with Vardr (`install.sh`).

**Enabling and disabling in the panel** (administrator, with a reason and password) overrides `enabled` from the file and is audited. "Restore from file" reverts the override.

The rule list has a search (title, id, file, tag) and filters: source (own, SigmaHQ, panel, built-in), state and level. An administrator can select rules – also all from the filter – and change them **in bulk**: enable, disable, set trial mode or restore the file setting. A bulk change always requires a reason and password and is audited as one entry.

### Trial mode

A rule in trial mode is evaluated on current events but **creates no alerts or notifications** – the detector only counts hits: by hour and computer, with the last event as an example. The results are on the *Detection rules → Rule trials* page:

| Verdict | When | What to do |
|---|---|---|
| too short | the trial has run for less than a day | wait |
| quiet | 0 hits | can be enabled |
| rare | less than 1 hit a day | review the examples, enable |
| moderate | 1–20 a day | check whether these are real events; possibly add exceptions to the rule |
| noisy | over 20 a day | do not enable without tuning |

A typical flow for SigmaHQ rules: *SigmaHQ* filter, levels *high* and *critical* → select all → *Trial mode*; after a week or two in *Rule trials* select the quiet and rare ones → *Enable*, the noisy ones → *Disable*.

- Trials run in the streaming engine (`SIEM_DETECTION_MODE` `stream` or `both`). Threshold rules count condition hits, without the threshold.
- An enabled rule set to trial stops alerting for the time of the trial – that is why it requires a reason and password like disabling.
- Hits are kept in `gjallarhorn.rule_trial_hits` for 35 days; restarting a trial counts from zero.
- Trials do not apply to correlations, built-in rules and correlation base rules.

## Built-in rules

They are not Sigma files – they run in the detector code, but are visible in the panel like rules (file "(built-in)"):

| Rule | Id | What it detects | Can be disabled in the panel |
|---|---|---|---|
| Lost connection to agent | `heimdall-agent-heartbeat-lost` | no heartbeat beyond the agent group threshold; closes itself when the agent is back | no (threshold in the group) |
| Agent tampering attempt | `heimdall-agent-tamper` | stop without a token, service permission change, killed process, forged token, no return after an upgrade | no (protection in the group) |
| Successful logon after a series of failures | `heimdall-success-after-failures` | ≥5 failed logons of a person in 30 min (any sources), then a successful one; further successful logons while the alert is open raise the counter | yes |
| Sign-in from a new country | `heimdall-signin-new-country` | a successful sign-in from a country outside the person's 30-day history (Entra ID) | yes |
| Silent event source | `heimdall-source-silent` | a syslog device or the cloud is silent longer than the longest gap of the last 7 days + 1 h | yes |
| Critical risk of a person or computer | `vardr-risk-critical` | the risk score of a person or computer enters the critical level ([Risk](panel.md#risk-of-people-and-computers)) | yes (also in the risk settings) |

Identifiers of rules from before the rename have the `heimdall-` prefix – the project's former name. They stay unchanged, because they link alert history, notification channel filters and panel overrides. Built-in rules have English texts in the code (`server/internal/detector/lang.go` and the files below).

Code: `server/internal/detector/heartbeat.go`, `tamper.go`, `correlate.go`, `silence.go`, `riskrule.go` (scoring: `internal/risk`). Correlations and the silent source read ClickHouse (`siem.auth_events`, `siem.events`), so they require `SIEM_DETECTOR_CH_PASSWORD`.

## Rules in the repository

| File | What it detects |
|---|---|
| `windows/security_brute_force_logon.yml` | ≥10 failed logons (4625) to an account in 5 min |
| `windows/security_brute_force_kerberos.yml` | a series of wrong Kerberos passwords (4771) |
| `windows/security_password_spraying.yml` | ≥5 different accounts from one address in 10 min |
| `windows/security_log_cleared.yml`, `system_eventlog_cleared.yml` | a cleared log (1102, 104) |
| `windows/security_user_created.yml` | account creation (4720) |
| `windows/security_privileged_group_member_added.yml` | added to a privileged group |
| `windows/system_service_install_suspicious.yml` | a service installed with a suspicious path (7045) |
| `windows/system_security_service_stopped.yml` | Sysmon stopped |
| `windows/proc_powershell_encoded_command.yml` | PowerShell with an encoded command |
| `windows/ps_script_suspicious_keywords.yml` | suspicious words in PowerShell scripts (4104) |
| `network/fortigate_vpn_brute_force.yml`, `fortigate_admin_login_failures.yml` | a series of failed VPN and FortiGate admin logins |
| `network/mikrotik_login_brute_force.yml` | a series of failed MikroTik router logins |
| `cross/password_spraying_multi_source.yml` | spraying from one address across AD, Entra, VPN and the router |
| `windows/proc_discovery_burst.yml` | discovery: ≥4 different tools (whoami, net, nltest, systeminfo…) on a computer in 10 min |
| `windows/proc_ad_discovery_tools.yml` | AD discovery: nltest /domain_trusts, `net group "domain admins"`, AdFind, BloodHound |
| `windows/system_service_remote_exec.yml` | lateral movement: PsExec / Impacket service (%COMSPEC%, ADMIN$) |
| `windows/proc_remote_exec_wmi_winrm.yml` | lateral movement: a shell started via WMI (wmiprvse) or WinRM (wsmprovhost) |
| `windows/security_ntlm_logon_many_hosts.yml` | lateral movement: NTLM network logons of one account on ≥5 computers in 10 min |
| `windows/ps_script_collection.yml` | collection: PowerShell with screen capture, clipboard, keystroke capture |
| `windows/proc_archive_with_password.yml` | collection: a password-protected 7-Zip/RAR archive |
| `windows/proc_lolbin_download.yml` | C2: file download with certutil or bitsadmin |
| `windows/proc_remote_access_tunnel.yml` | C2: AnyDesk, ScreenConnect, TeamViewer…, ngrok, chisel, plink -R |
| `windows/proc_exfil_cloud_tools.yml` | exfiltration: rclone copy/sync, MEGA, curl --upload-file |
| `network/fortigate_port_scan.yml` | reconnaissance: ≥20 denied ports from one address in 2 min |
| `network/fortigate_host_sweep.yml` | reconnaissance: ≥30 denied destination addresses from one address in 2 min |
| `windows/defender_threat_detected.yml` | Microsoft Defender detected a threat (1116, 1006, suspicious behaviour 1015); an alert per computer and threat name |
| `windows/defender_remediation_failed.yml` | Defender failed to remove a threat (1008, 1118, 1119) – critical |
| `windows/defender_protection_disabled.yml` | real-time protection or scanning disabled (5001, 5010, 5012), a blocked change attempt (5013) |
| `windows/defender_exclusion_added.yml` | a Defender exclusion added (5007 with `\Exclusions\`) |
| `windows/defender_asr_block.yml` | an ASR rule blocked an action (1121) |
| `correlation/new_account_privileged.yml` | correlation: an account created and added to a privileged group within an hour |
| `correlation/account_failures_many_sources.yml` | correlation: failed logons to one account from ≥4 addresses in 15 min (with its base rule) |

The *Resource Development* tactic (preparing the attacker's infrastructure – domains, servers, accounts outside the company) has no rules: it leaves no traces in the organisation's logs. The FortiGate scan rules require logging of denied traffic in the firewall policy.

## Importing SigmaHQ rules

[SigmaHQ](https://github.com/SigmaHQ/sigma) is an open, community-maintained base of several thousand Sigma rules. Vardr supports a subset of Sigma, so some rules load and some do not (e.g. unsupported modifiers or sources the agent does not collect). The import is manual: you copy selected directories, check them with the Vardr parser, drop those that fail, and deploy the rest **disabled**. Then you enable individual rules in the panel, after a test on history.

The rules go to `rules/sigmahq/`. The server bundle does not contain them – the import is the administrator's decision.

### Server from the installer

On a server installed from the bundle (`install.sh`) one script does the whole import – without the repository or Go:

```bash
sudo /opt/vardr/sigmahq-import.sh            # import or update
sudo /opt/vardr/sigmahq-import.sh --remove   # remove SigmaHQ rules
```

The script downloads SigmaHQ from GitHub, copies the categories listed below, drops `experimental`, `deprecated` and `unsupported` rules and those the Vardr parser does not support, disables the rest in the files, adds the source and license information and switches the new version of the rules directory (the detector loads it within 30 s). A Vardr upgrade carries the imported rules over to the new version. The same instructions are in the panel: *Detection rules → Import SigmaHQ rules*.

### Vardr repository

Vardr's tests (engine compatibility, corpus, ATT&CK tags, translations) skip this directory, and `TestImportedRules` makes sure the imported rules load without errors and are disabled in the files.

### Steps – PowerShell (in the project directory)

1. Download (or update: `git -C ../sigma pull`):

   ```powershell
   git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma
   ```

2. Copy the categories for the sources we collect (when updating, first `Remove-Item -Recurse rules/sigmahq` – panel enablements stay, because they are stored by rule `id`):

   ```powershell
   $dirs = 'windows/process_creation','windows/powershell/powershell_script','windows/builtin/security','windows/builtin/system','windows/builtin/windefend','windows/network_connection','windows/file/file_event','windows/dns_query','windows/registry/registry_set','cloud/azure/signin_logs','cloud/azure/audit_logs'; foreach ($d in $dirs) { $src = "../sigma/rules/$d"; if (Test-Path $src) { New-Item -ItemType Directory -Force "rules/sigmahq/$d" | Out-Null; Copy-Item "$src/*" "rules/sigmahq/$d/" -Recurse -Force } }
   ```

3. Mature rules only (status `stable` and `test`):

   ```powershell
   Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | Where-Object { Select-String -Path $_.FullName -Pattern '^status: (experimental|deprecated|unsupported)' -Quiet } | Remove-Item
   ```

4. Check with the parser and remove the rules Vardr does not support (the second command; then the first once more – the error count should show 0):

   ```powershell
   & "C:\Program Files\Go\bin\go.exe" run ./server/cmd/siem-detector check rules > check.txt; "OK: " + (Select-String -Path check.txt -Pattern '^OK').Count; "errors: " + (Select-String -Path check.txt -Pattern '^(?!OK|WARN)\S+\s+sigmahq/').Count
   ```

   ```powershell
   Select-String -Path check.txt -Pattern '^(?!OK|WARN)\S+\s+(sigmahq/[^\s:]+\.yml)' | ForEach-Object { "rules/" + $_.Matches[0].Groups[1].Value } | Sort-Object -Unique | Where-Object { Test-Path $_ } | Remove-Item
   ```

5. All imported rules disabled in the files (without this hundreds of rules would be enabled at once):

   ```powershell
   Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | ForEach-Object { [IO.File]::AppendAllText($_.FullName, "`nvardr:`n  enabled: false`n") }
   ```

6. Deployment (a bash script – via Git Bash):

   ```powershell
   & "C:\Program Files\Git\bin\bash.exe" deploy/lab/deploy.sh rules
   ```

### Steps – Git Bash

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma
for d in windows/process_creation windows/powershell/powershell_script windows/builtin/security windows/builtin/system windows/builtin/windefend windows/network_connection windows/file/file_event windows/dns_query windows/registry/registry_set cloud/azure/signin_logs cloud/azure/audit_logs; do [ -d "../sigma/rules/$d" ] && mkdir -p "rules/sigmahq/$d" && cp -r "../sigma/rules/$d/." "rules/sigmahq/$d/"; done
grep -rlE '^status: (experimental|deprecated|unsupported)' rules/sigmahq | xargs -r rm
go run ./server/cmd/siem-detector check rules > check.txt
grep -vE '^(OK|WARN)' check.txt | sed -nE 's/^[^ ]+ +(sigmahq\/[^ :]+\.yml).*/rules\/\1/p' | sort -u | xargs -r rm
find rules/sigmahq -name '*.yml' -exec sh -c 'printf "\nvardr:\n  enabled: false\n" >> "$1"' _ {} \;
deploy/lab/deploy.sh rules
```

### Enabling rules

The most convenient way is [trial mode](#trial-mode): select SigmaHQ rules (e.g. levels high and critical), start a trial, and after a week or two enable those that turned out quiet or rare. You can also check a single rule on history right away: the **Test** tab in the rule details (events from the last 7 days). A rule without false positives – enable it with the switch (administrator, audit entry). The panel setting survives a re-import, because it is stored by rule `id`. The engines evaluate only enabled rules – disabled ones put no load on detection.

Sysmon categories outside the list in step 2 (image loads, process access, pipes, WMI) are skipped: the agent does not collect them, and the engine does not support them. Rules on Event IDs the agent profile does not collect will load but will have no hits – a test on history shows this (0 events).

### License

SigmaHQ rules are licensed under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License): they may be used, modified and distributed, also commercially, provided the author (the `author` field), the source and the license are kept. Do not remove the `author` and `references` fields from the rules. For rules from `rules/sigmahq/` the panel shows the author, source (a link to the rule in SigmaHQ) and license in the rule and alert details, and notifications have a "Rule author" field – the license requires the author to be credited in messages from hits too. Vardr's own rules do not have this field. The `rules/sigmahq/` directory is in `.gitignore` and the bundle skips it: the decision to import belongs to the administrator, and the rules are not distributed with Vardr. `sigmahq-import.sh` writes the source and license information into this directory (`README.md`, `LICENSE.SigmaHQ.md`); when importing from the repository, add it yourself if you pass the directory on. The rule license does not apply to Vardr's code.
