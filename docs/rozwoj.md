# Rozwój

## Wymagania

- **Go** w wersji z `go.mod`. Jeden moduł `siem` dla wszystkich programów.
- **Docker** na serwerze – bazy do testów integracyjnych (ClickHouse 25.8, PostgreSQL 18) i budowanie obrazów.
- **Node.js LTS** do frontendu panelu (opcjonalnie lokalnie; `deploy.sh web` buduje go w kontenerze na VM).
- **Git Bash** na Windows (`deploy.sh` i skrypty).

## Budowanie

```powershell
# agent Windows (na Windows bez dodatkowych zmiennych)
go build -o bin/siem_agent.exe ./agent/cmd/siem_agent

# usługi serwera (Linux)
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -o bin/ ./server/cmd/... ./panel/cmd/siem-api ./agent/cmd/siem_collector ./agent/cmd/siem_connector

# narzędzia
go build -o bin/ ./server/cmd/siem-loadgen ./tools/cmd/...

# frontend (wynik w panel/web/dist, wbudowywany w siem-api przez embed)
cd panel/web; npm ci; npm run build
```

Wersję usług serwera ustawia `-ldflags "-X siem/internal/svc.Version=<wersja>"` (kolektor i konektor: `-X main.version=…`); `deploy.sh` bierze ją z `git describe`. Agent ma własny numer wersji w `agent/cmd/siem_agent/main.go` – podnoś go przy każdym wydaniu MSI (instalator nie aktualizuje tej samej wersji). MSI buduje `deploy.sh agent` (wixl w kontenerze, `deploy/lab/msi`).

## Testy

```powershell
go vet ./...
go test ./...
```

**Testy jednostkowe** nie potrzebują niczego poza Go. **Testy na prawdziwych bazach** są pomijane bez zmiennych środowiskowych:

| Zmienna | Testy |
|---|---|
| `SIEM_TEST_CH_ADDR`, `SIEM_TEST_CH_USER`, `SIEM_TEST_CH_PASSWORD` | zgodność silników detekcji (`TestEngineCompatibility`), korelacje i cisza źródła (`TestCorrelations`), łańcuch progów |
| `SIEM_TEST_PG_URL` | alerty (`internal/alerts`), archiwum (`internal/urd`), baza panelu (`panel/internal/api/store`) |

Bazy testowe w Dockerze:

```bash
docker run -d --name chtest -p 127.0.0.1:59000:9000 -e CLICKHOUSE_PASSWORD=test clickhouse/clickhouse-server:25.8
docker run -d --name pgtest -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=t postgres:18-alpine
```

```bash
SIEM_TEST_CH_ADDR=127.0.0.1:59000 SIEM_TEST_CH_PASSWORD=test \
SIEM_TEST_PG_URL="postgres://postgres:test@127.0.0.1:55432/t?sslmode=disable" \
go test -count=1 -p 1 -run 'Compat|Chain|Correlations|Postgres|PG' ./server/internal/detector ./internal/alerts ./internal/urd ./panel/internal/api/store
```

`-p 1`: testy dzielą jedną bazę PostgreSQL. Bez Dockera na stacji można zbudować binaria testów (`GOOS=linux go test -c`) i uruchomić je na VM obok kontenerów testowych.

**Najważniejsze testy:**

- `server/internal/detector/compat_test.go` – korpus zdarzeń (`testdata/`) przez oba silniki: każda reguła z `rules/` musi dawać te same trafienia w locie i w SQL.
- `server/internal/detector/correlate_test.go` – korelacje i cisza źródła na prawdziwym ClickHouse. Tabela logowań powstaje z tego samego skryptu co na serwerze (`03-auth-events.sh`); test pilnuje, żeby warunki logowań w skrypcie i w kodzie były zgodne.
- `internal/alerts/pg_test.go` – zapis alertów: łączenie, duplikaty, trafienia „tylko licznik”, równoległe zapisy jednego klucza (jeden alert), powiązane po osobie.
- `internal/decode` – próbki wszystkich wbudowanych dekoderów.
- `server/internal/normalize` – parser XML Windows, także fuzzing (`go test -fuzz FuzzParseWinEvent`).

**CI** (`.github/workflows/ci.yml`, każdy push):

- **Linux:** `gofmt`, `go vet`, testy z `-race`, testy na prawdziwych bazach (usługi ClickHouse i PostgreSQL), 60 s fuzzingu, budowanie usług.
- **Windows:** `go vet`, testy agenta, budowanie `siem_agent.exe` i `odczytaj.exe`.
- **Frontend:** `npm ci` i `npm run build` (TypeScript).

Wynik jest w zakładce *Actions* repozytorium.

## Konwencje

- **Język:** komentarze, komunikaty, logi i interfejs po polsku. Identyfikatory w kodzie po angielsku. Opisy commitów po angielsku.
- **Formatowanie:** `gofmt` (sprawdzane w CI); frontend sprawdza kompilator TypeScript (`npm run build`).
- **Komentarze** mówią „dlaczego” i odwołują się do etapu lub incydentu, który wymusił rozwiązanie (np. „etap 8: przy 7000 zdarzeń/s …”). Kod mówi „co”.
- **Programy serwera:** konfiguracja tylko ze zmiennych środowiskowych (`internal/svc`: `Env`, `EnvInt`, `EnvDuration`), log JSON (`svc.Logger`), metryki w `server/internal/metrics`, czyste zakończenie po SIGTERM.
- **Potwierdzanie wiadomości NATS** dopiero po wykonaniu pracy; każdy etap musi znosić duplikaty.
- **SQL:** wartości od użytkownika zawsze jako parametry; nazwy kolumn tylko z list dozwolonych (Mímir, reguły).
- **Zmiany zachowania** opisuj w `README.md` (instrukcje) i `docs/` (ten zestaw), przebieg prac w `docs/PODSUMOWANIE.md`.

## Jak dodać…

### …nowe źródło syslog

1. Dekoder w panelu albo w `internal/decode/builtin/<id>.yml` z próbkami ([dekodery.md](dekodery.md)).
2. Produkt dla reguł w `internal/detect/compile.go` (`products`).
3. Jeśli źródło ma logowania – warunki w `authFailureSQL`/`authSuccessSQL` (`server/internal/detector/correlate.go`) **i** w `deploy/lab/clickhouse/init/03-auth-events.sh`. `TestCorrelations` sprawdzi zgodność, a skrypt trzeba uruchomić na serwerze ponownie (tabela zostaje, zmienia się widok – usuń `siem.auth_events_mv` przed ponownym uruchomieniem).
4. Reguły w `rules/network/` i zdarzenia w korpusie testu zgodności.

### …nowe źródło API (konektor)

1. Klient API w `agent/internal/<źródło>` (wzór: `agent/internal/graph`), pętla z kursorem i zakładką w `siem-connector`. Zdarzenie ma źródło `<dostawca>:<rodzaj>` – rozszerz `decode.IsAPI` i `apiSourceSQL` w `server/internal/detector/silence.go`.
2. Dekoder `json` z `match.app: [<dostawca>:<rodzaj>]`.
3. Produkt i usługi w `internal/detect/compile.go`.
4. Symulator do laboratorium (wzór: `internal/entrasim`).

### …regułę wbudowaną

Wzór: `server/internal/detector/silence.go` (cisza źródła).

1. Opis dla panelu (`alerts.RuleInfo`, `Mode: "system"` albo `"correlation"` – ta druga jest wyłączana w panelu).
2. Funkcja sprawdzająca zwracająca `[]alerts.Hit` – czysta, testowana jednostkowo.
3. Gorutyna w `server/cmd/siem-detector/main.go` zapisująca przez `store.Record`.
4. Dopisanie do listy reguł synchronizowanej z panelem (`Infos` / `CorrelationInfos`).
5. Opis w `docs/reguly.md`.

### …migrację bazy

- **Saga:** nowy plik `NNN_opis.sql` w katalogu migracji właściciela schematu (`panel/internal/api/store/migrations`, `internal/alerts/migrations`, `internal/urd/migrations`). Pliki są wbudowane w program i stosowane przy starcie po kolei. Uprawnienia ról nadaje się w tej samej migracji. W testach PostgreSQL dopisz nową tabelę do listy czyszczonej przed testem.
- **ClickHouse:** zmiana w `deploy/lab/clickhouse/init/` (idempotentna: `IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`) i opis polecenia dla istniejących instalacji w [operacje.md](operacje.md#migracje). Schemat w testach (`compatDDL` w `compat_test.go`) musi odpowiadać serwerowi.

### …moduł panelu

1. Handler w `panel/internal/api/<moduł>_handlers.go`, trasa w `server.go` z rolą (`roleViewer`, `roleAnalyst`, `roleAdmin`). Zmiany zapisuj do audytu (`s.audit`); operacje wrażliwe – z ponownym hasłem.
2. Magazyn w `panel/internal/api/store` (+ migracja) i test na PostgreSQL.
3. Typy i wywołania w `panel/web/src/api.ts`, strona w `panel/web/src/pages`, trasa w `App.tsx`, pozycja menu w `Layout.tsx`.

## Laboratorium deweloperskie

- **VM** z całym stosem: `192.168.88.98` (Proxmox, 8 vCPU, 9,4 GB RAM, Ubuntu). Dostęp kluczem SSH, wdrażanie tylko przez `deploy.sh`.
- **Domena** `azujo.centrala`: kontroler domeny i stacja robocza z agentami, polityka audytu z GPO, Sysmon.
- **Router MikroTik** wysyła syslog do kolektora.
- **FortiGate i Entra ID** są symulowane (`fortisim`, `entrasim`).
- **Test agenta bez serwera:** `siem-ingest-stub` i `agent/configs/agent.lab.yaml`.
- **Test obciążenia:** [testy-obciazeniowe.md](testy-obciazeniowe.md).
