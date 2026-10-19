# Operacje

Opis dotyczy serwera laboratoryjnego (`deploy/lab`): jedna VM z Dockerem, cały stos w Docker Compose. Instalacja od zera krok po kroku jest w [README.md, „Serwer laboratoryjny”](../README.md#serwer-laboratoryjny-deploylab).

## Układ serwera

| Miejsce | Zawartość |
|---|---|
| `~/siem-lab/` | stos: `docker-compose.yml`, skrypty, init baz, konfiguracja Prometheusa, Grafany i NATS (kopiowane przez `deploy.sh config`) |
| `~/siem-lab/.env` | hasła i ustawienia (tylko na serwerze, w kopii zapasowej zaszyfrowane) |
| `~/siem-lab/certs/` | CA serwera, certyfikat serwera, CA agentów z kluczem (wystawianie certyfikatów przy rejestracji) |
| `~/siem-lab/bin/` | programy Linux budowane przez `deploy.sh` |
| `~/siem-lab/rules/` | reguły: `v<czas>/` i dowiązanie `current` |
| `~/siem-lab/collector/`, `connector/` | konfiguracja, certyfikaty i bufor kolektora i konektora |
| `/srv/heimdall/archive` | archiwum NIS2 (`SIEM_ARCHIVE_PATH`, osobny dysk) |
| `/srv/heimdall/backup` | kopie zapasowe przed wysyłką |
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
| `config` | pliki stosu z `deploy/lab` (bez `certs/`, `.env`, `bin/`, danych); crontab `@reboot boot.sh` |
| `rules` | reguły (sprawdzane przed wysłaniem), przełączenie atomowe |
| `web` | frontend panelu budowany w kontenerze Node na VM (potem cel `api`) |
| `ingest`, `normalizer`, `writer`, `archiver`, `detector`, `api` | program dla Linuksa z wersją z gita, obraz i restart usługi |
| `collector`, `connector` | kolektor i konektor |
| `agent` | `siem_agent.exe` i MSI do paczek panelu |
| `tools` | `odczytaj.exe` do eksportów archiwum |

Zmienne: `SIEM_LAB_HOST` (`siem@192.168.88.98`), `SIEM_LAB_KEY` (`~/.ssh/siem_lab`), `SIEM_LAB_DIR` (`~/siem-lab`). Wersja z niezatwierdzonymi zmianami ma dopisek `-dirty`.

**Kolejność:** zmiany schematu `gjallarhorn` stosuje detektor, więc wdrażaj **detektor przed panelem**. Zmiana `docker-compose.yml` wymaga `deploy.sh config`, a potem `docker compose up -d` na VM (odtwarza zmienione kontenery). Zmiana limitów JetStream (`nats/nats.conf`) wymaga `docker compose restart nats`, a zmiana alertów Grafany – restartu Grafany.

**Start po restarcie VM:** `boot.sh` (crontab `@reboot`) uruchamia `docker compose up -d` 30 s po starcie systemu; dziennik w `~/siem-lab/boot.log`.

## Agenci

- **Nowy agent:** panel → Bifröst → token i paczka ZIP. Na komputerze `siem_agent install -token …` albo MSI.
- **Aktualizacja:** nowa wersja MSI (każde wydanie musi mieć nowy numer wersji – instalator nie aktualizuje tej samej wersji). Chroniony agent przyjmuje aktualizację przez instalator bez tokenu (instalator zatrzymuje go jako SYSTEM).
- **Zatrzymanie, deinstalacja:** panel → agent → Token deinstalacji (ponowne hasło, powód). Token jest jednorazowy i ważny krótko.
- **Unieważnienie:** panel → agent → Unieważnij. Certyfikat trafia na listę odrzucanych przez ingest, a alert utraty łączności pomija agenta.
- **Kolektor i konektor** w laboratorium: `deploy/lab/service-enroll.sh collector|connector [grupa]` (jednorazowo po pierwszym wdrożeniu).
- **Polityka audytu i Sysmon w domenie:** `deploy/windows/heimdall-gpo.ps1`, `deploy/windows/sysmon.ps1`.

## Kopie zapasowe

`backup.sh` (crontab codziennie 02:15) tworzy paczkę zaszyfrowaną gpg (AES-256): zrzut Sagi, `certs/` (z kluczem CA agentów) i `.env`. Paczka idzie poza VM (`SIEM_BACKUP_REMOTE`, przez SSH) razem z przyrostami archiwum NIS2.

```bash
./backup.sh                 # kopia teraz
./backup.sh haslo init      # pierwsze hasło (pokazywane raz – zapisz poza serwerem)
./backup.sh haslo pokaz | zmien
./restore.sh <heimdall-….tar.gpg> [katalog z paczkami urd-…]   # odtworzenie na czystej VM
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
- **Alerty Grafany** (`grafana/provisioning/alerting/heimdall.yaml`): potok nie działa, detektor nie działa, archiwizator nie działa, kolejka NATS > 80%, ingest odmawia, silnik zapytań > 15 min w tyle, reguły z błędami, archiwum (niezgodności, brak weryfikacji, mało miejsca, archiwizacja wyłączona, zaplanowane osłabienie), dysk systemowy, kopie zapasowe. Alerty idą przez przekaźnik panelu na kanały powiadomień.
- **Panel → Himinbjörg:** stan usług i kolejek.
- **Logi:** `docker compose logs --since 10m <usługa>`; ostrzeżenia i błędy: `… | grep -E '"WARN"|"ERROR"'`.

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
