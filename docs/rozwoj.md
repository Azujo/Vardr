# Rozwój

## Wymagania

- **Go** w wersji z `go.mod`. Jeden moduł `siem` dla wszystkich programów.
- **Docker** na serwerze – bazy do testów integracyjnych (ClickHouse 25.8, PostgreSQL 18) i budowanie obrazów.
- **Node.js LTS** do frontendu panelu (opcjonalnie lokalnie; `deploy.sh web` buduje go w kontenerze na VM).
- **Git Bash** na Windows (`deploy.sh` i skrypty).

## Budowanie

```powershell
# agent Windows (na Windows bez dodatkowych zmiennych)
go build -o bin/vardr-agent.exe ./agent/cmd/vardr-agent

# usługi serwera (Linux)
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -o bin/ ./server/cmd/... ./panel/cmd/siem-api ./agent/cmd/siem_collector ./agent/cmd/siem_connector

# narzędzia
go build -o bin/ ./server/cmd/siem-loadgen ./tools/cmd/...

# frontend (wynik w panel/web/dist, wbudowywany w siem-api przez embed)
cd panel/web; npm ci; npm run build
```

Wersję usług serwera ustawia `-ldflags "-X siem/internal/svc.Version=<wersja>"` (kolektor i konektor: `-X main.version=…`); `deploy.sh` bierze ją z `git describe`. Agent ma własny numer wersji w `agent/cmd/vardr-agent/version.go` – podnoś go przy każdym wydaniu MSI (instalator nie aktualizuje tej samej wersji). MSI buduje `deploy.sh agent` (wixl w kontenerze, `deploy/lab/msi`).

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
- **Windows:** `go vet`, testy agenta, budowanie `vardr-agent.exe` i `odczytaj.exe`.
- **Frontend:** `npm ci` i `npm run build` (TypeScript).

Wynik jest w zakładce *Actions* repozytorium.

## Wydania

Wydanie to tag `vX.Y.Z` na `master` (opis zmian najpierw w `CHANGELOG.md`, sekcja `## [X.Y.Z] – data – tytuł`). Wypchnięcie tagu uruchamia `.github/workflows/release.yml`:

1. **Windows** – `vardr-agent.exe`, `vardr-mcp.exe`, `odczytaj.exe`; przy włączonym podpisywaniu – podpis Authenticode i sprawdzenie podpisu.
2. **Linux** – frontend, paczka serwera `deploy/vardr/build-bundle.sh` z programami Windows z kroku 1 (`VARDR_WINDOWS_BIN`), `SHA256SUMS`.
3. **Wydanie na GitHubie** – tytuł i opis z sekcji wersji w `CHANGELOG.md`, pliki: paczka serwera, `vardr-mcp.exe`, `odczytaj.exe`, `SHA256SUMS`. Ponowne uruchomienie (*Run workflow* z nazwą tagu) podmienia pliki istniejącego wydania.

Instalator MSI agenta nie jest w wydaniu – serwer buduje go przy instalacji z certyfikatem CA tej instalacji (z podpisanego `vardr-agent.exe`, sam plik MSI niepodpisany).

### Podpisywanie programów Windows

Niepodpisany, nowy plik `.exe` pobrany z przeglądarki Microsoft Defender i SmartScreen blokują heurystyką reputacji. Podpis Authenticode przez [Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/) (dawniej Trusted Signing):

1. W Azure: konto *Artifact Signing* (plan Basic), weryfikacja tożsamości (*Identity validation* – osoba albo firma), profil certyfikatu *Public Trust*.
2. Rejestracja aplikacji w Entra ID z poświadczeniem federacyjnym dla GitHub Actions (repozytorium, `refs/tags/*` albo środowisko) i rolą *Artifact Signing Certificate Profile Signer* na koncie podpisywania.
3. W repozytorium (*Settings → Secrets and variables → Actions*): sekrety `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`; zmienne `SIGNING=true`, `SIGNING_ENDPOINT` (np. `https://weu.codesigning.azure.net/` – region konta), `SIGNING_ACCOUNT`, `SIGNING_PROFILE`.

Bez `SIGNING=true` wydanie powstaje z programami niepodpisanymi. Podpis sprawdza się we Właściwościach pliku (*Podpisy cyfrowe*) albo `Get-AuthenticodeSignature vardr-mcp.exe`.

## Konwencje

- **Język:** komentarze w kodzie po polsku, identyfikatory i opisy commitów po angielsku. **Logi usług, błędy wewnętrzne i komunikaty programów serwera** – po angielsku. Teksty dla ludzi – w obu językach: panelu w plikach tłumaczeń, serwera przez `internal/lang` (niżej, „…tłumaczenie”). Dokumentacja po polsku (`docs/`) i po angielsku (`docs/en/` – przy zmianie zachowania popraw obie).
- **Formatowanie:** `gofmt` (sprawdzane w CI); frontend sprawdza kompilator TypeScript (`npm run build`).
- **Komentarze** mówią „dlaczego” i odwołują się do etapu lub incydentu, który wymusił rozwiązanie (np. „etap 8: przy 7000 zdarzeń/s …”). Kod mówi „co”.
- **Programy serwera:** konfiguracja tylko ze zmiennych środowiskowych (`internal/svc`: `Env`, `EnvInt`, `EnvDuration`), log JSON (`svc.Logger`), metryki w `server/internal/metrics`, czyste zakończenie po SIGTERM.
- **Potwierdzanie wiadomości NATS** dopiero po wykonaniu pracy; każdy etap musi znosić duplikaty.
- **SQL:** wartości od użytkownika zawsze jako parametry; nazwy kolumn tylko z list dozwolonych (Mímir, reguły).
- **Zmiany zachowania** opisuj w `docs/` i `docs/en/` (`README.md`/`README.pl.md` to tylko strona projektu), zmiany wersji w `CHANGELOG.md` (sekcja „Niewydane”), przebieg prac w `docs/PODSUMOWANIE.md`.

## Jak dodać…

### …nowe źródło syslog

1. Dekoder w panelu albo w `internal/decode/builtin/<id>.yml` z próbkami ([dekodery.md](dekodery.md)).
2. Produkt dla reguł w `internal/detect/compile.go` (`products`).
3. Jeśli źródło ma logowania – warunki w `authFailureSQL`/`authSuccessSQL` (`server/internal/detector/correlate.go`) **i** w `deploy/lab/clickhouse/init/03-auth-events.sh`. `TestCorrelations` sprawdzi zgodność. Skrypt odtwarza widok z nowymi warunkami przy ponownym uruchomieniu – instalator robi to przy każdej aktualizacji (w laboratorium: `docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/03-auth-events.sh`).
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

1. Handler w `panel/internal/api/<moduł>_handlers.go`, trasa w tabeli `routes.go` z uprawnieniem modułu (`can("<moduł>", "read|write")`) – z tej samej tabeli powstaje opis OpenAPI, a trasa z uprawnieniem jest od razu dostępna dla tokenów API (w granicach ich profilu). Zmiany zapisuj do audytu (`s.audit`); operacje wrażliwe – z ponownym hasłem (`s.reauth`, niedostępne dla tokenów).
2. Magazyn w `panel/internal/api/store` (+ migracja) i test na PostgreSQL.
3. Typy i wywołania w `panel/web/src/api.ts`, strona w `panel/web/src/pages`, trasa w `App.tsx`, pozycja menu w `Layout.tsx`.
4. Teksty strony w plikach tłumaczeń modułu (niżej).

### …tłumaczenie panelu

Panel tłumaczy się w przeglądarce ([i18next](https://www.i18next.com)) – serwer nie wykonuje żadnej pracy, a każdy język to zestaw statycznych plików ładowanych dopiero wtedy, gdy są potrzebne.

- **Pliki:** `panel/web/src/locales/<język>/<moduł>.json` (`common` – menu i elementy wspólne, `incidents`, …). Polski jest źródłem kluczy, angielski – językiem zapasowym: brakujący tekst w innym języku panel pokazuje po angielsku.
- **W kodzie:** `const { t } = useTranslation("<moduł>")` i `t("klucz", { zmienna })`; liczba mnoga przez `count` i klucze `_one`/`_few`/`_many`/`_other` (polski) albo `_one`/`_other` (angielski). Daty i liczby przez `formatDate`/`formatNumber` z `api.ts` – biorą format z bieżącego języka.
- **Serwer mówi kodami:** statusy, rodzaje i wpisy osi czasu zapisuj jako kody i szczegóły (`details`), a tekst składaj w panelu – wtedy każdy czyta je w swoim języku. Błędy API mają stały kod (`writeError(w, status, "kod", "opis po polsku")`); tłumaczenie kodu – w `locales/en/errors.json`. Nowy kod bez tłumaczenia zatrzyma test `TestErrorCodesTranslated`.
- **Kompletność:** `npm run build` (i `npm run check-locales`) sprawdza, czy angielski ma wszystkie klucze polskiego, i podaje procent przetłumaczenia pozostałych języków.
- **Nowy język:** skopiuj `locales/en` do `locales/<kod>`, przetłumacz pliki, dopisz język w `languages` (`panel/web/src/i18n.ts`) i w `panelLanguages` (`panel/internal/api/auth_handlers.go`). Niepełne tłumaczenie można wydać – brakujące teksty będą po angielsku.
- **Język konta:** użytkownik wybiera go w menu konta; zapis na koncie (`PUT /api/v1/account/language`), przed zalogowaniem – język przeglądarki.

### …tłumaczenie tekstów serwera

- **Logi i błędy wewnętrzne** – tylko po angielsku.
- **Teksty dla ludzi tworzone przez serwer** – w obu językach, `internal/lang`:
  - `lang.Pick(l, pl, en)` – wybór tekstu; język systemu: w panelu `syslang.Cache`, w usługach `langdb.System` (widok `system_language`, nowa rola potrzebuje `GRANT SELECT`);
  - `lang.Errorf(pl, en, args…)` – błąd z dwoma wersjami (walidacja ustawień, reguł, dekoderów); `Error()` daje polski, `lang.English(err)` angielski, w logach (slog) – angielski; API zwraca oba (`message`, `message_en`; w wynikach testów `error`, `error_en`);
  - `lang.L(pl, en)` – programy na komputerach (agent, czytnik eksportu) według języka systemu operacyjnego (`VARDR_LANG` wymusza); testy takich pakietów ustawiają `VARDR_LANG=pl` w `TestMain`.
- **Reguły:** `vardr.i18n.en` w pliku reguły ([reguly.md](reguly.md#rozszerzenia-vardra)); reguły wbudowane – teksty w `server/internal/detector`. Test `TestOwnRulesTranslated` pilnuje reguł z repozytorium.

## Laboratorium deweloperskie

- **VM** z całym stosem: `192.168.88.98` (Proxmox, 8 vCPU, 9,4 GB RAM, Ubuntu). Dostęp kluczem SSH, wdrażanie tylko przez `deploy.sh`.
- **Domena** `azujo.centrala`: kontroler domeny i stacja robocza z agentami, polityka audytu z GPO, Sysmon.
- **Router MikroTik** wysyła syslog do kolektora.
- **FortiGate i Entra ID** są symulowane (`fortisim`, `entrasim`).
- **Test agenta bez serwera:** `siem-ingest-stub` i `agent/configs/agent.lab.yaml`.
- **Test obciążenia:** [testy-obciazeniowe.md](testy-obciazeniowe.md).
