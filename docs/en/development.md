# Development

## Requirements

- **Go** in the version from `go.mod`. One `siem` module for all programs.
- **Docker** on the server – databases for integration tests (ClickHouse 25.8, PostgreSQL 18) and building images.
- **Node.js LTS** for the panel frontend (optional locally; `deploy.sh web` builds it in a container on the VM).
- **Git Bash** on Windows (`deploy.sh` and scripts).

## Building

```powershell
# Windows agent (on Windows without extra variables)
go build -o bin/vardr-agent.exe ./agent/cmd/vardr-agent

# server services (Linux)
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -o bin/ ./server/cmd/... ./panel/cmd/siem-api ./agent/cmd/siem_collector ./agent/cmd/siem_connector

# tools
go build -o bin/ ./server/cmd/siem-loadgen ./tools/cmd/...

# frontend (result in panel/web/dist, embedded into siem-api)
cd panel/web; npm ci; npm run build
```

The server service version is set with `-ldflags "-X siem/internal/svc.Version=<version>"` (collector and connector: `-X main.version=…`); `deploy.sh` and `build-bundle.sh` take it from `git describe`. The agent has its own version number in `agent/cmd/vardr-agent/main.go` – raise it with every MSI release (the installer does not upgrade the same version). The installation bundle: `deploy/vardr/build-bundle.sh` ([installation.md](installation.md#building-the-bundle)).

## Tests

```powershell
go vet ./...
go test ./...
```

**Unit tests** need nothing but Go. **Tests on real databases** are skipped without environment variables:

| Variable | Tests |
|---|---|
| `SIEM_TEST_CH_ADDR`, `SIEM_TEST_CH_USER`, `SIEM_TEST_CH_PASSWORD` | detection engine compatibility (`TestEngineCompatibility`), correlations and silent source (`TestCorrelations`), the threshold chain |
| `SIEM_TEST_PG_URL` | alerts (`internal/alerts`), archive (`internal/urd`), panel database (`panel/internal/api/store`) |

Test databases in Docker:

```bash
docker run -d --name chtest -p 127.0.0.1:59000:9000 -e CLICKHOUSE_PASSWORD=test clickhouse/clickhouse-server:25.8
docker run -d --name pgtest -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=t postgres:18-alpine
```

```bash
SIEM_TEST_CH_ADDR=127.0.0.1:59000 SIEM_TEST_CH_PASSWORD=test \
SIEM_TEST_PG_URL="postgres://postgres:test@127.0.0.1:55432/t?sslmode=disable" \
go test -count=1 -p 1 -run 'Compat|Chain|Correlations|Postgres|PG' ./server/internal/detector ./internal/alerts ./internal/urd ./panel/internal/api/store
```

`-p 1`: the tests share one PostgreSQL database. Without Docker on the workstation you can build test binaries (`GOOS=linux go test -c`) and run them on the VM next to the test containers.

**The most important tests:**

- `server/internal/detector/compat_test.go` – the event corpus (`testdata/`) through both engines: every rule from `rules/` must give the same hits in streaming and in SQL.
- `server/internal/detector/ownrules_test.go` – own rules load, imported ones are disabled, every own rule has an English translation (`TestOwnRulesTranslated`).
- `server/internal/detector/correlate_test.go` – correlations and silent source on a real ClickHouse. The sign-in table is created by the same script as on the server (`03-auth-events.sh`); the test keeps the sign-in conditions in the script and in the code consistent.
- `internal/alerts/pg_test.go` – recording alerts: merging, duplicates, "counter only" hits, parallel writes of one key (one alert), linking by person, bilingual texts.
- `internal/decode` – samples of all built-in decoders.
- `server/internal/normalize` – the Windows XML parser, also fuzzing (`go test -fuzz FuzzParseWinEvent`).
- `panel/internal/api` – among others `TestErrorCodesTranslated` (every API error code has an English translation in the panel).

**CI** (`.github/workflows/ci.yml`, every push):

- **Linux:** `gofmt`, `go vet`, tests with `-race`, tests on real databases (ClickHouse and PostgreSQL services), 60 s of fuzzing, building the services.
- **Windows:** `go vet`, agent tests, building `vardr-agent.exe` and `odczytaj.exe`.
- **Frontend:** `npm ci` and `npm run build` (TypeScript, translation completeness).

The result is in the repository's *Actions* tab.

## Conventions

- **Language:** code comments in Polish, identifiers and commit messages in English. **Service logs, internal errors and server program messages** – in English. Texts for people – in both languages: the panel in translation files, the server through `internal/lang` (below, "…translations"). Documentation in Polish (`docs/`) and English (`docs/en/` – when behaviour changes, update both).
- **Formatting:** `gofmt` (checked in CI); the frontend is checked by the TypeScript compiler (`npm run build`).
- **Comments** say "why" and refer to the stage or incident that forced the solution. The code says "what".
- **Server programs:** configuration only from environment variables (`internal/svc`: `Env`, `EnvInt`, `EnvDuration`), JSON log (`svc.Logger`), metrics in `server/internal/metrics`, a clean stop on SIGTERM.
- **NATS message acknowledgement** only after the work is done; every stage must tolerate duplicates.
- **SQL:** user values always as parameters; column names only from allow-lists (Mímir, rules).
- **Behaviour changes** go into `docs/` and `docs/en/` (`README.md`/`README.pl.md` are just the project page), version changes into `CHANGELOG.md` (the "Niewydane"/unreleased section).

## How to add…

### …a new syslog source

1. A decoder in the panel or in `internal/decode/builtin/<id>.yml` with samples ([decoders.md](decoders.md)).
2. A product for rules in `internal/detect/compile.go` (`products`).
3. If the source has sign-ins – conditions in `authFailureSQL`/`authSuccessSQL` (`server/internal/detector/correlate.go`) **and** in `deploy/lab/clickhouse/init/03-auth-events.sh`. `TestCorrelations` checks consistency, and the script must be rerun on the server (the table stays, the view changes – drop `siem.auth_events_mv` before rerunning).
4. Rules in `rules/network/` (with `vardr.i18n.en`) and events in the compatibility test corpus.

### …a new API source (connector)

1. An API client in `agent/internal/<source>` (pattern: `agent/internal/graph`), a loop with a cursor and overlap in `siem-connector`. The event has the source `<provider>:<kind>` – extend `decode.IsAPI` and `apiSourceSQL` in `server/internal/detector/silence.go`.
2. A `json` decoder with `match.app: [<provider>:<kind>]`.
3. The product and services in `internal/detect/compile.go`.
4. A simulator for the lab (pattern: `internal/entrasim`).

### …a built-in rule

Pattern: `server/internal/detector/silence.go` (silent source).

1. A description for the panel (`alerts.RuleInfo`, `Mode: "system"` or `"correlation"` – the latter can be disabled in the panel), with `I18n` for English.
2. A check function returning `[]alerts.Hit` – pure, unit-tested; texts in both languages (`Hit.I18n`).
3. A goroutine in `server/cmd/siem-detector/main.go` recording through `store.Record`.
4. Adding it to the rule list synchronized with the panel (`Infos` / `CorrelationInfos`).
5. A description in `docs/reguly.md` and `docs/en/rules.md`.

### …a database migration

- **Saga:** a new `NNN_description.sql` file in the migration directory of the schema owner (`panel/internal/api/store/migrations`, `internal/alerts/migrations`, `internal/urd/migrations`). Files are embedded in the program and applied at start in order. Role privileges are granted in the same migration. In PostgreSQL tests add a new table to the list cleaned before the test.
- **ClickHouse:** a change in `deploy/lab/clickhouse/init/` (idempotent: `IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`) and a description of the command for existing installations in [operations.md](operations.md#migrations). The schema in tests (`compatDDL` in `compat_test.go`) must match the server.

### …a panel module

1. A handler in `panel/internal/api/<module>_handlers.go`, a route in the `routes.go` table with a module permission (`can("<module>", "read|write")`) – the OpenAPI description is built from the same table, and a route with a permission is available to API tokens right away (within their profile). Record changes in the audit log (`s.audit`); sensitive operations – with password re-entry (`s.reauth`, not available to tokens).
2. A store in `panel/internal/api/store` (+ a migration) and a PostgreSQL test.
3. Types and calls in `panel/web/src/api.ts`, a page in `panel/web/src/pages`, a route in `App.tsx`, a menu item in `Layout.tsx`.
4. Page texts in the module's translation files (below).

### …panel translations

The panel is translated in the browser ([i18next](https://www.i18next.com)) – the server does no work, and each language is a set of static files loaded only when needed.

- **Files:** `panel/web/src/locales/<language>/<module>.json` (`common` – menu and shared elements, `incidents`, …). Polish is the source of keys, English is the fallback language: a text missing in another language is shown in English.
- **In code:** `const { t } = useTranslation("<module>")` and `t("key", { variable })`; plurals via `count` and the keys `_one`/`_few`/`_many`/`_other` (Polish) or `_one`/`_other` (English). Dates and numbers via `formatDate`/`formatNumber` from `api.ts` – they take the format from the current language.
- **The server speaks in codes:** statuses, kinds and timeline entries are stored as codes and details (`details`), and the text is composed in the panel – so everyone reads them in their own language. API errors have a fixed code (`writeError(w, status, "code", "Polish description")`); the code translation is in `locales/en/errors.json`. A new code without a translation fails the `TestErrorCodesTranslated` test.
- **Completeness:** `npm run build` (and `npm run check-locales`) checks that English has all the Polish keys and reports the translation percentage of other languages.
- **New language:** copy `locales/en` to `locales/<code>`, translate the files, add the language to `languages` (`panel/web/src/i18n.ts`) and to `panelLanguages` (`panel/internal/api/auth_handlers.go`). An incomplete translation can be released – missing texts will be in English.
- **Account language:** the user picks it in the account menu; stored on the account (`PUT /api/v1/account/language`), before sign-in – the browser language.

### …server-side translations

- **Logs and internal errors** – English only.
- **Texts for people created by the server** – in both languages, `internal/lang`:
  - `lang.Pick(l, pl, en)` – choosing a text; the system language: in the panel `syslang.Cache`, in services `langdb.System` (the `system_language` view; a new role needs `GRANT SELECT`);
  - `lang.Errorf(pl, en, args…)` – an error with two versions (validation of settings, rules, decoders); `Error()` gives Polish, `lang.English(err)` English, and English in logs (slog); the API returns both (`message`, `message_en`; in test results `error`, `error_en`);
  - `lang.L(pl, en)` – programs on computers (agent, export reader) according to the operating system language (`VARDR_LANG` forces it); tests of such packages set `VARDR_LANG=pl` in `TestMain`.
- **Rules:** `vardr.i18n.en` in the rule file ([rules.md](rules.md#vardr-extensions)); built-in rules – texts in `server/internal/detector`.

## Development lab

- **A VM** with the whole stack: `192.168.88.98` (Proxmox, 8 vCPU, 9.4 GB RAM, Ubuntu). SSH key access, deployment only via `deploy.sh`.
- **A domain** `azujo.centrala`: a domain controller and a workstation with agents, audit policy from GPO, Sysmon.
- **A MikroTik router** sends syslog to the collector.
- **FortiGate and Entra ID** are simulated (`fortisim`, `entrasim`).
- **Agent test without a server:** `siem-ingest-stub` and `agent/configs/agent.lab.yaml`.
- **Load tests:** [testy-obciazeniowe.md](../testy-obciazeniowe.md) (Polish).
