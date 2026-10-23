# Operacje

Opis dotyczy serwera laboratoryjnego (`deploy/lab`): jedna VM z Dockerem, cały stos w Docker Compose. Instalacja od zera krok po kroku jest w [laboratorium.md, „Serwer laboratoryjny”](laboratorium.md#serwer-laboratoryjny-deploylab); instalacja serwera z paczki: [instalacja.md](instalacja.md).

## Układ serwera

| Miejsce | Zawartość |
|---|---|
| `~/siem-lab/` | stos: `docker-compose.yml`, skrypty, init baz, konfiguracja Prometheusa, Grafany i NATS (kopiowane przez `deploy.sh config`) |
| `~/siem-lab/.env` | hasła i ustawienia (tylko na serwerze, w kopii zapasowej zaszyfrowane) |
| `~/siem-lab/certs/` | CA serwera, certyfikat serwera, CA agentów z kluczem (wystawianie certyfikatów przy rejestracji) |
| `~/siem-lab/bin/` | programy Linux budowane przez `deploy.sh` |
| `~/siem-lab/rules/` | reguły: `v<czas>/` i dowiązanie `current` |
| `~/siem-lab/collector/`, `connector/` | konfiguracja, certyfikaty i bufor kolektora i konektora |
| `/srv/vardr/archive` | archiwum NIS2 (`SIEM_ARCHIVE_PATH`, osobny dysk; laboratorium: `/srv/heimdall/archive` – nazwa sprzed zmiany nazwy projektu) |
| `/srv/vardr/backup` | kopie zapasowe przed wysyłką (`SIEM_BACKUP_DIR`; laboratorium: `/srv/heimdall/backup`) |
| `~/.vardr-backup.pass` | hasło kopii zapasowych (tylko dla właściciela) |
| wolumeny Dockera | dane NATS, ClickHouse, Saga, Prometheus, Grafana |

**Zmienne `.env`:** hasła baz (`SAGA_ADMIN_PASSWORD`, `SAGA_DB_PASSWORD`, `SAGA_ARCHIVER_PASSWORD`, `SAGA_DETECTOR_PASSWORD`, `CLICKHOUSE_ADMIN_USER`/`_PASSWORD`, `CLICKHOUSE_WRITER_PASSWORD`, `CLICKHOUSE_PANEL_PASSWORD`, `CLICKHOUSE_DETECTOR_PASSWORD`, `CLICKHOUSE_GRAFANA_PASSWORD`), `GRAFANA_ADMIN_PASSWORD`, `SIEM_ALERT_RELAY_TOKEN`, `SIEM_PUBLIC_SERVER` (adres w paczkach agentów), `SIEM_EVENTS_TTL_DAYS`, `SIEM_RAW_TTL_DAYS`, `SIEM_ARCHIVE_PATH`, `SIEM_ARCHIVE_EXPORT_PATH`, `SIEM_DETECTION_MODE`, `SIEM_BACKUP_REMOTE`, `SIEM_PPROF`. Pozostałe ustawienia usług mają wartości domyślne w compose ([programy.md](programy.md)).

**Porty:**

| Port | Usługa | Dostęp |
|---|---|---|
| 8443 | `siem-ingest` (agenci, mTLS) | sieć |
| 8444 | panel | sieć |
| 514 UDP/TCP | kolektor syslog | sieć (lista `allow`) |
| 3000 | Grafana | sieć |
| 9090 | Prometheus | tylko VM (`ssh -L 9090:127.0.0.1:9090`) |
| 8123 | ClickHouse HTTP | tylko VM |
| 8222 | monitoring NATS | tylko VM |
| 8099 | symulator Graph (`entrasim`) | tylko VM |
| 4222, 9000, 5432, 9100, 8081 | NATS, ClickHouse, Saga, metryki, przekaźnik alertów | tylko sieć Dockera |

## Wdrażanie

Jedyna droga zmian na serwerze to `deploy/lab/deploy.sh` ze stacji (Git Bash). Dzięki temu VM nie rozjeżdża się z repozytorium.

```bash
deploy/lab/deploy.sh                    # config, rules i usługi serwera (bez web, agent, collector, connector, tools)
deploy/lab/deploy.sh detector api       # wybrane cele
```

| Cel | Działanie |
|---|---|
| `config` | pliki stosu z `deploy/lab` (bez `certs/`, `.env`, `bin/`, danych); crontab `@reboot boot.sh`; plik hasła kopii i `backup-state/` |
| `rules` | reguły (sprawdzane przed wysłaniem), przełączenie atomowe |
| `web` | frontend panelu budowany w kontenerze Node na VM (potem cel `api`) |
| `ingest`, `normalizer`, `writer`, `archiver`, `detector`, `api`, `backup` | program dla Linuksa z wersją z gita, obraz i restart usługi |
| `collector`, `connector` | kolektor i konektor |
| `agent` | `vardr-agent.exe` i MSI do paczek panelu |
| `tools` | `odczytaj.exe` do eksportów archiwum |

Zmienne: `SIEM_LAB_HOST` (`siem@192.168.88.98`), `SIEM_LAB_KEY` (`~/.ssh/siem_lab`), `SIEM_LAB_DIR` (`~/siem-lab`). Wersja z niezatwierdzonymi zmianami ma dopisek `-dirty`.

**Kolejność:** zmiany schematu `gjallarhorn` stosuje detektor, więc wdrażaj **detektor przed panelem**. Zmiana `docker-compose.yml` wymaga `deploy.sh config`, a potem `docker compose up -d` na VM (odtwarza zmienione kontenery). Zmiana limitów JetStream (`nats/nats.conf`) wymaga `docker compose restart nats`, a zmiana alertów Grafany – restartu Grafany.

**Start po restarcie VM:** `boot.sh` (crontab `@reboot`) uruchamia `docker compose up -d` 30 s po starcie systemu; dziennik w `~/siem-lab/boot.log`.

## Agenci

- **Nowy agent:** panel → Bifröst → token i paczka ZIP. Na komputerze `vardr-agent install -token …` albo MSI.
- **Aktualizacja:** nowa wersja MSI (każde wydanie musi mieć nowy numer wersji – instalator nie aktualizuje tej samej wersji). Chroniony agent przyjmuje aktualizację przez instalator bez tokenu (instalator zatrzymuje go jako SYSTEM).
- **Zatrzymanie, deinstalacja:** panel → agent → Token deinstalacji (ponowne hasło, powód). Token jest jednorazowy i ważny krótko.
- **Unieważnienie:** panel → agent → Unieważnij. Certyfikat trafia na listę odrzucanych przez ingest, a alert utraty łączności pomija agenta.
- **Kolektor i konektor** w laboratorium: `deploy/lab/service-enroll.sh collector|connector [grupa]` (jednorazowo po pierwszym wdrożeniu).
- **Polityka audytu i Sysmon w domenie:** `deploy/windows/vardr-gpo.ps1`, `deploy/windows/sysmon.ps1`.

## Kopie zapasowe

Kopie wykonuje usługa `siem-backup` (kontener `backup`), a ustawia się je w panelu: **Administracja → Kopie zapasowe**.

| Ustawienie | Możliwości |
|---|---|
| harmonogram | co 1–12 godzin, codziennie albo co tydzień o podanej godzinie (czas serwera) |
| zawartość | baza Saga, konfiguracja (`certs/` z kluczem CA agentów, `.env`), przyrosty archiwum NIS2 (tylko do miejsca docelowego), dane Grafany |
| retencja | osobno lokalnie i w miejscu docelowym: dni oraz najwyżej N kopii (0 – bez limitu); najnowsza kopia zostaje zawsze; paczki archiwum wygasają tylko po dniach |
| miejsce docelowe | tylko lokalnie, SFTP (klucz wygenerowany przez usługę, własny klucz albo hasło), SMB, S3 (MinIO, AWS, Backblaze…) |

**Działanie:**

- Panel zapisuje ustawienia w Sadze (zawsze z ponownym hasłem, do audytu). Usługa sprawdza je co 15 s.
- Hasła i klucze do miejsca docelowego panel szyfruje kluczem publicznym usługi, więc nie odczyta ich ani panel, ani baza.
- Kopia to paczka `vardr-RRRRMMDD-GGMM-k<id>.tar.gpg` zaszyfrowana hasłem kopii (gpg AES-256). Lokalnie leży w `SIEM_BACKUP_DIR` (domyślnie `/srv/vardr/backup`, laboratorium: `/srv/heimdall/backup`), w miejscu docelowym w `config/`, a przyrosty archiwum w `urd/`.
- Wysyłka idzie przez rclone. Klucz serwera SFTP jest zapamiętywany przy pierwszym połączeniu (odcisk widać w panelu); jego późniejsza zmiana zatrzymuje wysyłkę. Żeby zaakceptować nowy klucz, usuń wpis z `~/siem-lab/backup-state/known_hosts`.
- Panel pokazuje historię kopii z wynikiem i ma przyciski „Zrób kopię teraz” i „Sprawdź połączenie”.
- Stan usługi (klucz do sekretów, klucz SSH, `known_hosts`) jest w `~/siem-lab/backup-state`. Utrata tego katalogu oznacza nowe klucze: sekrety trzeba wpisać ponownie, a nowy klucz SSH dopisać na serwerze kopii.

**Przywracanie z panelu** (zakładka *Przywracanie*):

1. **Lista kopii.** Panel pokazuje kopie lokalne i w miejscu docelowym; lista odświeża się co 15 min i po każdej kopii.
2. **Sprawdzenie zawartości.** Usługa odszyfrowuje kopię hasłem kopii (kopię z miejsca docelowego najpierw pobiera) i pokazuje, co w niej jest.
3. **Przywróć.** Administrator wybiera części do przywrócenia: bazę Saga razem z konfiguracją (w `.env` są hasła ról bazy) i/lub dane Grafany. Potwierdza wpisaniem `PRZYWRÓĆ` i hasłem.
4. **Przygotowanie.** Usługa kopii robi kopię obecnego stanu (domyślnie), sprawdza kopię i zostawia zlecenie w `<kopie>/.przywracanie/zlecenie`.
5. **Przywrócenie.** `restore.sh --zlecenie` (cron co minutę, wpis dodaje `deploy.sh config`) zatrzymuje usługi korzystające z bazy (panel, detektor, archiwizator, usługa kopii), przywraca części i uruchamia stos. Wynik zapisuje w Sadze, a dziennik w `~/siem-lab/restore.log`.

Po przywróceniu bazy panel jest w stanie z dnia kopii: konta i sesje też, więc trzeba się zalogować ponownie. Alerty, agenci i zmiany ustawień późniejsze niż kopia znikają. Zdarzeń w ClickHouse i archiwum NIS2 przywracanie nie zmienia; archiwum odtwarza się na czystym serwerze ręcznie (`restore.sh <kopia> <katalog urd>`). Usługa kopii nie ma dostępu do Dockera – zatrzymać usługi może tylko skrypt na serwerze.

**Archiwum NIS2 po przywróceniu bazy.** Spis archiwum (schemat `urd`) wraca do chwili zrzutu, a segmenty i manifesty zapisane później zostają na dysku bez wpisu – weryfikacja zgłosiłaby je jako „dodane poza archiwizatorem”. Dlatego:

1. `restore.sh` po odtworzeniu bazy zostawia zlecenie w `urd.recoveries` z oknem czasu: od zrzutu (czas z nagłówka zrzutu, 10 min zapasu) do przywrócenia.
2. Archiwizator przy starcie, zanim zamknie kolejną godzinę, przyjmuje do spisu pliki z tego okna: manifest – gdy przedłuża łańcuch (numer, godzina, hash poprzednika) i jego segmenty mają zgodne sumy; segment bez manifestu – gdy format i sumy SHA-256 wszystkich paczek się zgadzają (trafi do najbliższego manifestu). Potem od razu weryfikuje archiwum.
3. Pliki spoza okna, uszkodzone albo bez dowodu ciągłości zostają zgłaszane. W panelu (*Urd*) administrator decyduje o nich: **przyjmij do archiwum** (te same sprawdzenia) albo **odłóż do kwarantanny** (`archive/quarantine/<czas>/…`, plik zachowany poza łańcuchem). Decyzja wymaga opisu przyczyny i hasła.

Nic nie jest usuwane ani przepisywane: wynik weryfikacji, która wykryła niezgodność, zostaje w historii, a każda operacja to osobny wpis (zakładka *Obsługa niezgodności*, audyt panelu) oraz plik w `archive/recoveries/` – ten przetrwa kolejne przywrócenie bazy i trafia do eksportu dla audytora (`obsluga-niezgodnosci/`). Kopia sprzed tej zmiany (bez tabeli `urd.recoveries`) nie dostanie zlecenia automatycznego – pliki rozstrzyga się wtedy w panelu.

```bash
./backup.sh                 # kopia teraz (zlecenie dla usługi, czeka na wynik)
./backup.sh password init   # pierwsze hasło (pokazywane raz – zapisz poza serwerem); dawniej: haslo init
./backup.sh password show | change   # dawniej: haslo pokaz | zmien (polskie polecenia nadal działają)
./restore.sh <vardr-….tar.gpg> [katalog z paczkami urd-…]   # odtworzenie na czystej VM
./restore.sh --zlecenie     # przywrócenie zlecone w panelu (uruchamia cron)
```

Kopia nie zawiera zdarzeń w ClickHouse (kilka dni, odtwarzalne z archiwum przez replay) ani kolejek NATS (agenci dosyłają zaległe zdarzenia sami). Alerty Grafany pilnują, czy kopia powstała i trafiła poza VM w ciągu 26 h.

## Retencja

| Dane | Ustawienie | Zmiana |
|---|---|---|
| zdarzenia i kwarantanna w ClickHouse | `SIEM_EVENTS_TTL_DAYS` (lab 5) | `.env`, potem `./clickhouse/retention.sh` |
| surowy XML zdarzeń | `SIEM_RAW_TTL_DAYS` (lab 2, ≤ zdarzenia) | jw. |
| tabela logowań | udane logowania Windows 1 dzień, reszta jak zdarzenia | `retention.sh` |
| zdarzenia odtworzone | `SIEM_REPLAY_TTL_DAYS` (7) | compose |
| archiwum NIS2 | polityka w panelu (Urd), granice `SIEM_ARCHIVE_MIN/MAX_RETENTION_DAYS` | panel (skrócenie z 24 h opóźnieniem) |
| alerty zamknięte | `SIEM_ALERT_RETENTION_DAYS` (365) | compose |

Planowanie dysku: ok. 125 B na zdarzenie w ClickHouse z surowym XML (ok. 75 GB na dobę przy 7000 zdarzeń/s), archiwum ok. 120 B na zdarzenie (ok. 100 GB na dobę przy 10 000/s).

## Migracje

- **Saga:** automatyczne przy starcie usług (`siem-api` – `public`, `siem-detector` – `gjallarhorn`, `siem-archiver` – `urd`), pod blokadą doradczą.
- **ClickHouse – nowa instalacja:** skrypty `clickhouse/init/*.sh` przy pierwszym starcie (pusty wolumen).
- **ClickHouse – istniejąca baza:** skrypty init są bezpieczne do ponownego uruchomienia:

  ```bash
  docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/02-replay.sh
  docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/03-auth-events.sh
  ```

  Zmiana klucza sortowania `siem.events` (instalacje sprzed etapu 8): `bash clickhouse/events-order.sh`.

## Monitorowanie

- **Grafana** (`:3000`): pulpity „SIEM – przegląd zdarzeń” i „SIEM – zdrowie potoku” (przepływ przez etapy, odmowy, kolejki, opóźnienia, CPU i pamięć usług, ClickHouse).
- **Alerty Grafany** (`grafana/provisioning/alerting/vardr.yaml`): potok nie działa, detektor nie działa, archiwizator nie działa, kolejka NATS > 80%, ingest odmawia, silnik zapytań > 15 min w tyle, reguły z błędami, archiwum (niezgodności, brak weryfikacji, mało miejsca, archiwizacja wyłączona, zaplanowane osłabienie), dysk systemowy, kopie zapasowe. Alerty idą przez przekaźnik panelu na kanały powiadomień.
- **Panel → Himinbjörg:** stan usług i kolejek.
- **Logi:** `docker compose logs --since 10m <usługa>`; ostrzeżenia i błędy: `… | grep -E '"WARN"|"ERROR"'`. Logi usług i komunikaty skryptów serwera są po angielsku; teksty zapisywane dla panelu (wyniki kopii, weryfikacji archiwum) – w języku systemu.

## Diagnostyka

| Objaw | Gdzie patrzeć | Typowa przyczyna |
|---|---|---|
| agenci dostają 503 | kolejka NATS (`siem_queue_fill_ratio`), zaległość konsumenta | zatrzymany etap (writer, archiwizator), pełny dysk archiwum |
| zaległość rośnie przy stałym ruchu | monitor (`pending`), CPU | VM wysycona; dziennik zapytań ClickHouse (co czyta najwięcej) |
| silnik zapytań w tyle | `siem_detector_index_lag_seconds`, log detektora | przeciążony ClickHouse, masowy atak na te same konta |
| brak alertów z reguły | panel → Reguły (błędy, wyłączona?), test reguły | błąd w regule, zły `logsource`, pole o innej nazwie |
| zdarzenia syslog jako `syslog.generic` | Mímir `dataset:syslog.generic` | brak dekodera dla urządzenia |
| kwarantanna rośnie | panel → Kwarantanna | zmiana formatu logów urządzenia, błąd dekodera |
| agent „zatrzymany bez tokenu” | strona agenta, alert sabotażu | ktoś zatrzymał usługę; sprawdzić dziennik ochrony |
| ClickHouse `MEMORY_LIMIT_EXCEEDED` | `system.query_log` (`exception_code = 241`) | zbyt szerokie zapytanie, mutacja `DELETE` na dużej tabeli |
| usługi nie wstały po restarcie VM | `~/siem-lab/boot.log`, `docker compose ps` | Docker nie podniósł kontenera – `boot.sh` robi `up -d` |

Polecenia ClickHouse i Sagi na VM:

```bash
docker compose exec clickhouse bash -c 'clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD"'
docker compose exec saga psql -U saga_admin -d saga
docker run --rm --network siem_default natsio/nats-box:0.18.1 nats -s nats://nats:4222 stream ls
```
