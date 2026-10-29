# Decoders

A decoder turns a non-Windows message into a normalized event. It handles two kinds of messages: syslog from the collector (firewalls, routers) and JSON records from the API connector (Entra ID). Decoders are YAML files:

- **built into** the normalizer program (`internal/decode/builtin/`: `fortigate`, `mikrotik`, `linux`, `pfsense`, `cisco-asa`, `entra-signin`, `entra-audit`; device setup – [Sources with a built-in decoder](#sources-with-a-built-in-decoder));
- **from the panel** (*Decoders*, administrator), kept in Saga with a version history and delivered to normalizers through the NATS KV `SIEM_DECODERS` within seconds, without a restart.

A panel decoder with the same `id` as a built-in one replaces it. "Restore the built-in version" reverts this. Code: `internal/decode`.

## How the normalizer picks a decoder

1. **Header.** A syslog message is split into a header (RFC 3164, RFC 5424 or just `<PRI>`): priority, time, host, program, PID and content. An API record has no header – the program is the connector source (`entra:signin`, `entra:audit`).
2. **Choice.** Decoders are checked from the highest `priority`. The first one whose `match` conditions fit wins.
3. **No decoder.** A syslog message without a matching decoder goes to ClickHouse as the `syslog.generic` dataset (just the content and header). An API record without a decoder goes to quarantine.
4. **Parser.** The decoder parses the content with its parser; if the content does not fit the parser (e.g. invalid JSON), the event goes to quarantine with the reason. After fixing the decoder it can be reprocessed (panel → Quarantine).

Every event gets the header fields in `fields` (`syslog.peer` – the sender address, `syslog.app`, `syslog.severity`, `syslog.facility`, `syslog.format`) plus `decoder.id` and `decoder.version`. A header time without a zone is interpreted in the `SIEM_SYSLOG_TZ` zone (default Europe/Warsaw).

Decoder validation errors (in the editor, wizard and tests) are shown in the account language.

## Format

```yaml
id: mikrotik                      # 2–64 characters: lowercase letters, digits, . _ -
title: MikroTik RouterOS – sign-ins, DHCP, firewall
description: |
  …
version: 2                        # increase on every change (visible in the event)
priority: 50                      # higher is checked earlier
dataset: mikrotik.routeros        # event.dataset of the events; windows.* and syslog.generic are reserved
match: …
parser: …
fields: …                         # mapping to common fields
set: …                            # constant field values
outcome: …                        # event.outcome from a field value
time: …                           # event time from the content
samples: […]                      # sample messages – decoder test
```

### match – when the decoder fits

All given conditions must be met (AND):

| Condition | Meaning |
|---|---|
| `peer: [192.168.88.1/32, 10.0.0.0/8]` | the sender address is in one of the networks |
| `host: [MikroTik]` | host name from the header (case-insensitive) |
| `app: [sshd]` | program name from the header (for API: the source, e.g. `entra:signin`) |
| `app_regex: '^(system\|firewall)(,.*)?$'` | an RE2 expression on the program name |
| `contains: ['logid=', 'devname=']` | the content contains all fragments |
| `regex: '…'` | an RE2 expression on the content |
| `any: [ {…}, {…} ]` | any of the alternatives (each a set of conditions as above, without a nested `any`) |

Conditions should be narrow enough for the decoder not to capture other devices' messages. The panel shows overlaps: a test on the latest unrecognised messages with the full decoder set.

### parser – parsing the content

| `type` | Action | Options |
|---|---|---|
| `kv` | `key=value` pairs (quoted values may contain spaces) – FortiGate | – |
| `json` | a JSON object; nested fields as `a.b.c`, arrays with an index (`targetResources.0.userPrincipalName`) | – |
| `csv` | columns separated by a separator | `separator` (one character), `columns: [..]` |
| `regex` | the first matching pattern; named groups `(?P<name>…)` are fields | `patterns: [{regex, set}]` – `set` holds constant fields for that pattern (e.g. `event.action: login`) |
| `audit` | a Linux Audit (auditd) event: the `type=… msg=audit(…)` records of one event; record fields, ENRICHED format translations (upper case) and normalized fields: `action`, `outcome`, `user`, `target_user`, `cmdline`, `file.path`, `src_ip`, `dest_ip`, `key`, `audit.ms` (time) – decoder `linux-audit` | – |
| `none` | no parsing (the content only in `message`) | – |

All parser fields go to `fields` under their names (except the reserved header and decoder names). In rules and in Mímir they are available as `fields.name`.

### fields – mapping to common fields

```yaml
fields:
  host.name: devname
  user.name: [user, srcuser, dstuser]     # the first non-empty one in the list
  source.ip: [srcip, remip]
  event.action: action
  event.code: logid
  message: [msg, logdesc]
```

Targets: `host.name`, `user.name`, `user.domain`, `source.ip`, `event.action`, `event.code` (a number), `event.provider`, `process.name`, `message` and any additional fields (e.g. `source.geo.country_iso_code`, `azure.app`), which go to `fields`. From `user.name` the normalizer derives the person (`user.identity`).

### set, outcome, time

```yaml
set:                       # constant values (e.g. for the whole decoder)
  event.action: sign-in

outcome:                   # event.outcome from the first non-empty field
  field: [status, action]
  failure: [failed, deny, ssl-login-fail]
  success: [success, accept, ssl-login]
  otherwise: failure       # optional: the outcome for values outside the lists (e.g. error code ≠ 0)

time:                      # event time from the content (more precise than the header)
  fields: [date, time, tz]                   # joined with a space
  layout: "2006-01-02 15:04:05 -0700"        # a Go layout or unix | unix_ms | unix_ns | rfc3339
  timezone: Europe/Warsaw                    # when the time has no zone
```

`event.outcome` is key for correlations and sign-in rules: `failure` and `success` must be set for sign-ins, so that the event goes to the sign-in table (`siem.auth_events`) and to the "success after failures" rules. Sign-in conditions for new sources are added in `server/internal/detector/correlate.go` and `deploy/lab/clickhouse/init/03-auth-events.sh` (a test keeps them consistent).

### samples

Samples are real messages (with the syslog header). When saving in the panel every sample must match `match` and be parsed by the parser – a decoder with a non-matching sample will not be saved. Samples of built-in decoders are checked by tests (`internal/decode`).

## Decoder wizard

A decoder for a new device can be built without writing YAML and regular expressions: **Decoders → Wizard from samples** (unrecognised messages from the last 7 days or pasted ones) or **Quarantine → decoder wizard** at a group of syslog messages.

1. **Samples.** The wizard splits the syslog headers and recognises the content kind: text, `key=value` pairs or JSON (it can be changed).
2. **Marking fields.**
   - *Text:* select a fragment of the message with the mouse and click a label, or drag the label onto the selection. Labels: time, user, domain, source and destination address, port, computer, action, outcome, code, program, content, custom field, **any** (a variable fragment, not stored – e.g. a protocol) and **recognition** (a fixed fragment by which the decoder will recognise these messages). Each kind of message (e.g. successful and failed sign-in) is marked separately – separate patterns are created, each with its own action and outcome.
   - *key=value and JSON:* a label at each field; "require" – a recognition condition.
3. **Settings.** Id, name, dataset, priority, recognition conditions (program, host, sender from the header), time format (recognised from the example, also a time made of several fields) and outcome values (success/failure).
4. **Check.** The definition is tested on all samples while marking: ✓ recognised with fields, ✗ not (a click opens it for marking as another pattern), ↷ handled by another decoder.
5. **Saving.** "Save and deploy" (administrator) or "Open in editor" to polish the YAML by hand.

The wizard builds a pattern from the text around the selections: whitespace and numbers are generalised, long stretches are replaced with an anchor from the last words before the field. A word that changes in messages of this kind and is not a field should be marked as "any" – otherwise the pattern covers only messages with the same word (the check shows this).

## Sources with a built-in decoder

All of them send syslog to the collector address (UDP or TCP 514); the device network must be in the collector's `syslog.allow`. Rules for these sources: [rules.md](rules.md#rules-in-the-repository).

| Source | Decoder | `event.dataset` | `product` in rules |
|---|---|---|---|
| FortiGate | `fortigate` | `fortinet.fortigate` | `fortigate` |
| MikroTik RouterOS | `mikrotik` | `mikrotik.routeros` | `mikrotik` |
| Linux servers (rsyslog) | `linux` | `linux.auth` | `linux` |
| pfSense, OPNsense | `pfsense` | `pfsense.firewall` | `pfsense` (`opnsense`) |
| Cisco ASA, Firepower (FTD) | `cisco-asa` | `cisco.asa` | `cisco` (`asa`) |
| IIS (W3C files, Windows agent – not syslog) | `iis` | `iis.access` | `iis`, `category: webserver` – see [agent.md](agent.md#iis-logs-since-version-010) |

Sign-ins from these sources (fields `event.action: login` and `event.outcome`, on Cisco ASA also `vpn-connect`) go to the sign-in table and to the "success after failures" correlation together with AD, Entra ID and VPN.

### Linux via rsyslog

The decoder recognises the programs `sshd` (also `sshd-session` from OpenSSH 9.8+), `sudo`, `su`, `useradd`, `userdel`, `usermod`, `groupadd`, `gpasswd`, `passwd`, `chpasswd` and `systemd-logind`: SSH logins (with the `invalid_user` field for non-existent accounts), sudo commands and denials (`process.command_line`, `target_user`, `sudo_error`), su, failed PAM authentications, sessions and account and group changes (`target_user`, `group`). On the server – the file `/etc/rsyslog.d/90-vardr.conf`:

```
# auth and authpriv to the Vardr collector; disk queue when the connection is down
auth,authpriv.* action(type="omfwd" target="collector.company.com" port="514" protocol="tcp"
                       template="RSYSLOG_SyslogProtocol23Format"
                       queue.type="LinkedList" queue.filename="vardr" queue.maxDiskSpace="100m"
                       queue.saveOnShutdown="on" action.resumeRetryCount="-1")
```

The `RSYSLOG_SyslogProtocol23Format` template (RFC 5424) sends the time with its time zone – the default RFC 3164 format has none and the time is read in the `SIEM_SYSLOG_TZ` zone (a server in UTC would be shifted). Then `sudo systemctl restart rsyslog`. A system without rsyslog (journald only, e.g. minimal Debian) – install the `rsyslog` package; it reads the systemd journal. Check: `logger -p authpriv.notice "vardr test"` – the message shows up in Mímir (`host.name` of the server).

### Syslog over TLS

Plain syslog travels as clear text without authentication – on a network you do not control (a branch over the internet, a shared network) send it over TLS instead (RFC 5425, port 6514). The collector accepts TLS next to UDP/TCP; devices that support it (rsyslog, syslog-ng, FortiGate with `mode reliable` and `enc-algorithm`) move to the new port, the rest stay on 514.

1. The collector certificate (self-signed, 10 years; the name and address devices use to reach the server):
   ```bash
   cd /opt/vardr
   sudo docker compose run --rm collector tls-cert -dir /collector -host collector.company.com,10.0.0.5
   ```
   A certificate from your company CA works too – point `tls_cert`/`tls_key` to it.
2. In `collector/collector.yaml`, in the `syslog` section:
   ```yaml
   tls: ":6514"
   tls_cert: certs/syslog.crt
   tls_key: certs/syslog.key
   ```
   and `sudo docker compose restart collector`. Port 6514 is published in `docker-compose.yml`; on the firewall open it only to device networks.
3. On the device, trust `collector/certs/syslog.crt` as the CA. rsyslog (package `rsyslog-gnutls`):
   ```
   global(DefaultNetstreamDriverCAFile="/etc/rsyslog.d/vardr-ca.crt")
   auth,authpriv.* action(type="omfwd" target="collector.company.com" port="6514" protocol="tcp"
                          StreamDriver="gtls" StreamDriverMode="1"
                          StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="collector.company.com"
                          template="RSYSLOG_SyslogProtocol23Format"
                          queue.type="LinkedList" queue.filename="vardr" queue.maxDiskSpace="100m"
                          queue.saveOnShutdown="on" action.resumeRetryCount="-1")
   ```

**Device certificate (optional).** TLS alone encrypts and proves the collector's identity to the device, but anyone in the `allow` networks can still send. When devices have certificates from your company CA, add `tls_client_ca: certs/devices-ca.crt` (the collector refuses connections without a valid certificate from that CA) and optionally `tls_client_names: ["fw1.company.com", "srv-www"]` (allowed CN or DNS names from the certificate). In rsyslog: `DefaultNetstreamDriverCertFile` and `DefaultNetstreamDriverKeyFile` in `global(...)`. Refused connections are counted as `tls_failed` in the collector log (`syslog: liczniki`).

Messages received over TLS have the source `syslog:tls` in Mímir; decoders work the same as for UDP/TCP.

### pfSense and OPNsense

- **pfSense:** *Status → System Logs → Settings*: *Enable Remote Logging*, server `collector:514`, contents *Firewall Events* and *System Events* (web GUI logins). Blocked traffic is logged by the default block rule (*Log packets matched from the default block rules*); own rules – the *Log* option.
- **OPNsense:** *System → Settings → Logging → Remote*: a new destination (UDP or TCP, port 514), applications `filter` (filterlog) and `audit` (web GUI logins); firewall rules with the *Log* option.

The decoder recognises `filterlog` entries (IPv4 and IPv6: `fw_action` – pass/block/reject, `interface`, `direction`, `proto`, addresses and ports, `dst_port`) and successful and failed web GUI logins. SSH logins to the firewall are recognised by the `linux` decoder.

### Cisco ASA and Firepower

```
logging enable
logging timestamp
logging trap informational
logging host inside 10.0.0.20
```

(`10.0.0.20` – the collector, `inside` – the interface it is behind.) `logging timestamp` gives the exact event time; without it the receive time is used. With syslog over TCP (`logging host inside 10.0.0.20 tcp/514`) the ASA by default holds traffic when the syslog server is unreachable – add `logging permit-hostdown` or stay with UDP. Firepower (FTD): syslog settings in *Platform Settings* in FMC.

The decoder sets `event.code` to the message number and recognises: denied and permitted access list traffic (106023, 106100, 106001/106006/106007/106015), administrator logins (605004/605005, 611101/611102), AAA and VPN authentications (113004, 113005, 113015), AnyConnect sessions (113039 – `vpn-connect`, 722051, 113019) and administrator commands (111008, 111010). Other messages – `event.action: other` with the text.

## A new device – step by step

1. **Logs.** On the device set syslog to the collector address (UDP/TCP 514). Add the device network to the collector's `syslog.allow`.
2. **Samples.** Messages without a decoder appear in Mímir as `dataset:syslog.generic`. Copy a few different ones.
3. **New decoder.** In the panel (*Decoders → New decoder*) enter a `match` that selects only this device (e.g. `host`, `peer` or a characteristic content fragment) and a parser – or use the wizard.
4. **Test.** Test on the samples and on unrecognised messages, complete `fields`, `outcome` and `time`. Save with a reason.
5. **Check.** New messages have the decoder's `dataset`. Reprocess the quarantine entries (if any).
6. **Rules.** A rule for a new source needs `logsource.product`. A new product is one entry in `internal/detect/compile.go` (`products`: product name → `event.dataset`) and a new detector version.

A decoder proven in use is worth moving to `internal/decode/builtin/` (with samples in a test), so that it is in every installation.
