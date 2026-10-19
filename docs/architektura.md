# Architektura

Heimdall to zestaw małych programów w Go, połączonych kolejką NATS JetStream. Zdarzenia przechodzą przez kolejne etapy, a każdy etap potwierdza wiadomość dopiero po wykonaniu swojej pracy. Awaria albo restart dowolnej usługi nie gubi więc zdarzeń: czekają w kolejce, a agenci trzymają je w buforze dyskowym, dopóki serwer ich nie przyjmie.

## Składniki

```
 komputery Windows          urządzenia sieciowe             chmura
 ┌──────────────┐           ┌──────────────┐               ┌────────────┐
 │ siem_agent   │           │ MikroTik,    │──syslog 514──▶│siem-       │
 │ (usługa)     │           │ FortiGate    │               │collector   │
 └──────┬───────┘           └──────────────┘               └─────┬──────┘
        │ HTTPS + mTLS, paczki gzip, heartbeat                   │   ┌────────────┐
        │                                                        │   │siem-       │◀── Microsoft Graph
        ▼                                                        ▼   │connector   │    (Entra ID)
 ┌───────────────────────────── siem-ingest :8443 ◀──────────────────┴────────────┘
 │  /v1/ingest → SIEM_RAW (paczka bez zmian)
 │  /v1/heartbeat → SIEM_HEARTBEATS
 ▼
 SIEM_RAW ──▶ siem-normalizer ──▶ SIEM_EVENTS ──┬──▶ siem-writer ──▶ ClickHouse siem.events (+ quarantine)
    │                                           │                       └─ widok → siem.auth_events
    │                                           └──▶ siem-detector (w locie) ──▶ Saga: gjallarhorn.*
    └──▶ siem-archiver ──▶ archiwum NIS2 (pliki)     siem-detector (zapytania, korelacje) ◀── ClickHouse
                                                                     │
 siem-api (panel Hliðskjálf :8444) ◀── Saga, ClickHouse, NATS ◀──────┘ (outbox → Discord/e-mail)
 Prometheus ◀── metryki :9100 wszystkich usług ──▶ Grafana :3000 (pulpity, alerty)
```

| Program | Rola | Stan |
|---|---|---|
| `siem_agent` (Windows) | czyta dzienniki zdarzeń, wysyła paczki, chroni się przed zatrzymaniem | stan odczytu i bufor dyskowy w `C:\ProgramData\Heimdall` |
| `siem-collector` | odbiera syslog z urządzeń, wysyła jak agent | bufor dyskowy w katalogu kolektora |
| `siem-connector` | pobiera logi z API chmury (Entra ID przez Graph), wysyła jak agent | kursor odczytu i bufor |
| `siem-ingest` | przyjmuje paczki i heartbeaty (mTLS), wkłada do NATS | bezstanowy |
| `siem-normalizer` | zamienia surowe zdarzenia na wspólny model, dekoduje syslog i API | bezstanowy (dekodery i tożsamości z NATS KV) |
| `siem-writer` | zapisuje zdarzenia do ClickHouse | bezstanowy |
| `siem-detector` | detekcja w locie, silnik zapytań, korelacje, reguły wbudowane | alerty i stan progów w Sadze |
| `siem-archiver` | archiwum NIS2: oryginalne paczki w segmentach z łańcuchem hashy | pliki archiwum, spis w Sadze (`urd`) |
| `siem-api` | panel WWW i API, rejestracja agentów, wysyłka powiadomień | Saga (schemat `public`) |

Szczegóły każdego programu: [programy.md](programy.md).

## Przepływ zdarzenia

1. **Agent** czyta zdarzenie z dziennika Windows (EvtSubscribe, z zakładką na ostatni rekord), renderuje XML, dokleja je do paczki. Paczka jest wysyłana, gdy zbierze `max_events` zdarzeń albo minie czas. Agent 0.7.1 trzyma małą paczkę (poniżej 50 zdarzeń) do 10 s, żeby stacje o małym ruchu nie wysyłały tysięcy drobnych paczek. Paczka idzie gzipem przez HTTPS z certyfikatem klienta (mTLS). Do potwierdzenia przez serwer leży w buforze dyskowym.
2. **siem-ingest** sprawdza certyfikat (czy wystawiony przez CA agentów i nieunieważniony – lista w NATS KV `SIEM_REVOKED_CERTS`), rozmiar i schemat paczki, i publikuje ją bez zmian do strumienia `SIEM_RAW` (temat `siem.raw.<agent>`). Odpowiada 200 dopiero po potwierdzeniu zapisu przez NATS. Przy zapełnionej kolejce odpowiada 503, przy zbyt wielu równoległych żądaniach 429; agent ponawia z odczekaniem.
3. **siem-normalizer** (konsument `normalizer` na `SIEM_RAW`) rozpakowuje paczkę i zamienia każde zdarzenie na `model.Event`: XML Windows parserem z mapą pól, syslog i API dekoderami (`internal/decode`). Ustala osobę (`internal/identity`). Zdarzenia, których nie da się znormalizować, trafiają do kwarantanny razem z oryginałem i powodem. Wynik publikuje jako paczkę znormalizowaną do `SIEM_EVENTS` (`siem.events.<agent>`).
4. **siem-writer** (konsument `clickhouse-writer` na `SIEM_EVENTS`) zbiera paczki do 20 000 wierszy albo 1 s i zapisuje jednym INSERT-em do `siem.events` i `siem.quarantine`. Widok zmaterializowany odkłada logowania do `siem.auth_events`.
5. **siem-detector** (konsument `detector` na `SIEM_EVENTS`) ocenia każde zdarzenie regułami w locie. Osobno co minutę pyta ClickHouse (silnik zapytań i korelacje), co 30 s sprawdza heartbeaty agentów, co 5 min ciszę źródeł. Alerty zapisuje w Sadze; nowy alert dostaje wpis w `gjallarhorn.outbox`.
6. **siem-archiver** (konsument `archiver` na `SIEM_RAW`) zapisuje oryginalne paczki do segmentów archiwum i potwierdza wiadomości dopiero po zapisie segmentu na dysk.
7. **siem-api** wysyła wpisy z outboxu na kanały powiadomień, a panel czyta zdarzenia z ClickHouse i alerty z Sagi.

Heartbeat agenta (co minutę: wersja, stan kanałów, bufor, limity, ochrona) idzie przez `/v1/heartbeat` do strumienia `SIEM_HEARTBEATS`. Panel (`fleetsync`) aktualizuje z niego stan agentów, a detektor ocenia utratę łączności i sabotaż.

### Gwarancja dostarczenia

- Agent usuwa zdarzenia z bufora dopiero po odpowiedzi 200, a serwer odpowiada 200 dopiero po zapisie w NATS. Zakładka odczytu dziennika przesuwa się po potwierdzeniu.
- Każdy etap potwierdza wiadomość po wykonaniu pracy, więc po awarii wiadomość wraca. Możliwe są duplikaty, nie straty.
- Duplikaty usuwa ClickHouse (`ReplacingMergeTree`, klucz zawiera `event_id`), detekcja (para reguła–zdarzenie trafia do alertu raz) i archiwum (identyfikator paczki).
- Zatrzymany konsument (np. archiwizator) blokuje usuwanie wiadomości z kolejki – strumienie mają retencję „interest”. Gdy kolejka się zapełni, ingest odpowiada 503, a agenci czekają z buforem.

## NATS JetStream

| Strumień | Tematy | Konsumenci | Zawartość |
|---|---|---|---|
| `SIEM_RAW` | `siem.raw.<agent>` | `normalizer`, `archiver` | paczki agentów bez zmian (gzip + JSON, kontrakt v1) |
| `SIEM_EVENTS` | `siem.events.<agent>` | `clickhouse-writer`, `detector` | paczki znormalizowane (`model.Batch`, gzip + JSON) |
| `SIEM_HEARTBEATS` | `siem.heartbeat.<agent>` | panel (`fleetsync`) | ostatni heartbeat każdego agenta |
| `SIEM_REPLAY_RAW`, `SIEM_REPLAY_EVENTS` | `siem.replay.raw.>`, `siem.replay.events.>` | `normalizer-replay`, `writer-replay` | odtwarzanie z archiwum do `siem.events_replay` |

Magazyny klucz–wartość (NATS KV):

| Magazyn | Pisze | Czyta | Zawartość |
|---|---|---|---|
| `SIEM_DECODERS` | panel | normalizatory | dekodery syslog zmienione w panelu |
| `SIEM_IDENTITY` | panel | normalizatory, archiwizator | domeny organizacji, aliasy kont, konta wspólne |
| `SIEM_REVOKED_CERTS` | panel | ingest | unieważnione certyfikaty agentów |

Temat `siem.reprocess` (request–reply): panel prosi normalizator o ponowne przetworzenie wpisu z kwarantanny.

Limity kolejek: `SIEM_QUEUE_RAW_MAX_MB`, `SIEM_QUEUE_EVENTS_MAX_MB` (domyślnie po 8 GB), `SIEM_QUEUE_MAX_AGE`. Konfiguracja serwera NATS: `deploy/lab/nats/nats.conf` (`max_file_store` 21 GB – rezerwacje strumieni muszą się w nim zmieścić).

## Magazyny danych

### ClickHouse (baza `siem`)

| Tabela | Silnik | Klucz / partycje | Retencja | Co zawiera |
|---|---|---|---|---|
| `events` | ReplacingMergeTree(ingested) | `ORDER BY (event_dataset, toStartOfHour(ingested), host_name, timestamp, event_id)`, partycja dzienna po `ingested` | `SIEM_EVENTS_TTL_DAYS` (lab: 5), surowy XML `SIEM_RAW_TTL_DAYS` (2) | zdarzenia znormalizowane |
| `quarantine` | MergeTree | `(ingested, agent_id)` | jak zdarzenia | zdarzenia nieznormalizowane z oryginałem |
| `auth_events` | ReplacingMergeTree | `(outcome, event_dataset, ingested, event_id)` | udane logowania Windows 1 dzień, reszta jak zdarzenia | logowania (dla korelacji), zasilane widokiem `auth_events_mv` |
| `events_replay` | ReplacingMergeTree | jak `events` | `SIEM_REPLAY_TTL_DAYS` (7) od odtworzenia | zdarzenia odtworzone z archiwum |

Schemat: `deploy/lab/clickhouse/init/` (skrypty uruchamiane przy pierwszym starcie; na istniejącej bazie – patrz [operacje.md](operacje.md#migracje)). Kolumny `events`: czas zdarzenia i przyjęcia, `event_id`, `agent_id`, `event_dataset`, `event_code`, `event_provider`, `event_action`, `event_outcome`, `host_name`, `user_name`, `user_domain`, `user_identity`, `source_ip` (IPv6, IPv4 jako `::ffff:`), proces i linia poleceń, `message`, `fields` (mapa pól źródłowych), `raw` (oryginał), `truncated`, `parser_version`, `time_quality`.

Konta ClickHouse: `siem_writer` (zapis), `siem_detector` (odczyt z limitami czasu i pamięci), `siem_panel` (odczyt, limit 30 s, 1–2 GB pamięci, 100 000 wierszy wyniku), `grafana` (odczyt).

### PostgreSQL – Saga

| Schemat | Właściciel migracji | Tabele |
|---|---|---|
| `public` | `siem-api` (`panel/internal/api/store/migrations`) | `users`, `sessions`, `audit_log`, `agents`, `agent_groups`, `agent_assignments`, `agent_certs`, `enrollment_tokens`, `agent_uninstall_tokens`, `notify_channels`, `notify_log`, `syslog_decoders`, `syslog_decoder_versions`, `quarantine_jobs`, `quarantine_outcomes`, `identity_domains`, `identity_aliases`, `identity_shared_accounts` |
| `gjallarhorn` | `siem-detector` (`internal/alerts/migrations`) | `alerts`, `alert_events`, `alert_activity`, `outbox`, `threshold_events`, `index_state`, `rules`, `rule_versions`, `rule_overrides`, `rule_errors` |
| `urd` | `siem-archiver` (`internal/urd`) | `segments`, `manifests`, `verifications`, `policy`, `policy_changes`, `exports`, `replays`, `group_membership`, `archiver_state` |

Każda usługa łączy się własną rolą z minimalnymi uprawnieniami (`saga_admin` tylko do migracji i administracji, `siem_api`, `siem_detector`, `siem_archiver`; opis: [README.md, „Role bazy Saga”](../README.md#role-bazy-saga)). Migracje stosuje usługa przy starcie, pod blokadą doradczą, więc kilka kopii nie wykona ich równolegle. Kolejność wdrażania: najpierw detektor (schemat `gjallarhorn`), potem panel.

### Archiwum NIS2 (Urd)

Pliki w `SIEM_ARCHIVE_PATH` (lab: `/srv/heimdall/archive`): oryginalne paczki agentów w segmentach (do 64 MB albo 30 s), każdy segment z hashem SHA-256 i odwołaniem do hasha poprzedniego (łańcuch). Manifest dnia spina segmenty; codziennie o 7:00 hash manifestu idzie na kanał powiadomień jako kotwica poza systemem. Weryfikacja co 6 h sprawdza część archiwum w ramach budżetu odczytu. Eksport dla audytora to paczka `.tar` z czytnikiem `odczytaj.exe`. Odtworzenie (replay) przepuszcza wybrane segmenty przez osobny potok do `siem.events_replay`. Szczegóły: [README.md, „Archiwum NIS2”](../README.md#archiwum-nis2--urd-siem-archiver).

## Detekcja (Gjallarhorn)

`siem-detector` ma kilka mechanizmów zapisujących alerty do tej samej bazy:

| Mechanizm | Co robi | Jak często | `engine` alertu |
|---|---|---|---|
| silnik w locie | reguły Sigma na każdym zdarzeniu z `SIEM_EVENTS`; progi w pamięci (stan w `threshold_events`, odtwarzany po restarcie) | na bieżąco | `stream` |
| silnik zapytań | te same reguły jako SQL na `siem.events` (zdarzenia przyjęte od punktu kontrolnego, z zakładką); nadrabia przerwy, spóźnione zdarzenia i limity pamięci progów | co minutę, 2 min za bieżącym czasem | `index_query` |
| korelacje | „udane po nieudanych”, „nowy kraj” na `siem.auth_events` | co minutę, okno 15 min | `correlation` |
| utrata łączności | heartbeat agenta starszy niż próg grupy | co 30 s | `system` |
| sabotaż agenta | dziennik ochrony z heartbeatu, zatrzymania bez tokenu | co 30 s | `system` |
| cisza źródła | urządzenie syslog albo chmura milczy dłużej niż zwykle | co 5 min | `system` |

Zapis alertu (`internal/alerts`):

1. **Rezerwacja.** Para (reguła, zdarzenie) jest rezerwowana w `alert_events`, więc ponownie dostarczone zdarzenie albo to samo zdarzenie z obu silników nie liczy się dwa razy.
2. **Łączenie.** Trafienie z kluczem grupy (`group_by`) łączy się z otwartym alertem tej reguły i klucza z okna `suppress`. Licznik `hits` rośnie, zdarzenie jest dołączane do osi alertu.
3. **Nowy alert.** Gdy nie ma otwartego alertu do połączenia, powstaje nowy alert z wpisem w outboxie.

Równoległe zapisy z różnych mechanizmów czekają na siebie tylko przy tym samym kluczu (blokady doradcze transakcji). Panel wysyła wpisy z outboxu na kanały (Discord, z filtrem poziomu i limitem „burzy alertów”).

Szczegóły pisania reguł: [reguly.md](reguly.md).

## Panel i zarządzanie flotą

- Agent rejestruje się jednorazowym tokenem z panelu (`/enroll/v1/register`): sam generuje klucz, panel wystawia certyfikat podpisany CA agentów. Przed wygaśnięciem certyfikat jest odnawiany (`/enroll/v1/renew`).
- Konfigurację (profil zdarzeń, limity, ochronę, tokeny deinstalacji) agent pobiera z panelu (`/enroll/v1/config`) według swojej grupy i trzyma jej kopię lokalnie.
- Unieważnienie agenta w panelu trafia do NATS KV, które czyta ingest – od tej chwili paczki agenta są odrzucane.
- Moduły panelu: [panel.md](panel.md).

## Bezpieczeństwo

- **mTLS wszędzie od agenta:** serwer przyjmuje tylko certyfikaty z CA agentów, agent sprawdza certyfikat serwera z własnym CA.
- **Hasła i sekrety** są w `.env` na serwerze (poza repozytorium) i w kopiach zaszyfrowanych gpg. W bazie są tylko skróty haseł (argon2id), tokenów rejestracyjnych i tokenów deinstalacji.
- **Role baz** mają minimalne uprawnienia; panel czyta ClickHouse kontem tylko do odczytu z limitami, wartości z zapytania idą jako parametry.
- **Operacje wrażliwe w panelu** (osłabienie polityki archiwum, wyłączenie reguły, token deinstalacji) wymagają ponownego podania hasła i trafiają do audytu; osłabienie archiwum działa z 24-godzinnym opóźnieniem.
- **Ochrona agenta:** usługa z zawężonymi uprawnieniami, jednorazowe tokeny zatrzymania i deinstalacji, dziennik prób w heartbeacie, alert przy sabotażu.
- **Archiwum NIS2:** łańcuch hashy, dzienna kotwica poza systemem, weryfikacja okresowa.

## Struktura repozytorium

Jeden moduł Go (`siem`). Kod w `agent/internal/`, `server/internal/` i `panel/internal/` jest prywatny dla swojej części (Go nie pozwala go importować z innej). Wspólne pakiety są w `internal/`.

```
agent/
  cmd/siem_agent/        agent Windows: instalator, usługa, ochrona, polecenia
  cmd/siem_collector/    kolektor syslog (Linux/Windows)
  cmd/siem_connector/    konektor API (Entra ID przez Microsoft Graph)
  configs/               agent.example.yaml (profil z załącznika B), agent.lab.yaml
  internal/              config, core (paczkowanie), shipper (HTTPS + mTLS), spool (bufor
                         dyskowy), winevt (Event Log), logwatch, sysmon, syslog, graph,
                         hostagent (wspólny szkielet kolektora i konektora), managed
                         (konfiguracja z panelu), enrollment, heartbeat, guard (ochrona),
                         limits, logging, secure, setup, state, status, timesync, source
server/
  cmd/                   siem-ingest, siem-normalizer, siem-writer, siem-detector,
                         siem-archiver, siem-loadgen
  internal/              bus (NATS), queue, ingest, normalize, chwriter, detector,
                         archiver, loadgen, metrics
panel/
  cmd/siem-api/          backend panelu z wbudowanym frontendem
  internal/              api (+ store: Saga, migracje), events (Mímir), enroll (certyfikaty),
                         fleetsync (heartbeaty), notify (kanały), status (stan systemu)
  web/                   frontend: React + TypeScript + Mantine (Vite)
internal/                contract (paczka agent → serwer), model (zdarzenie), decode
                         (dekodery syslog/API, wbudowane w builtin/), decodekv, detect
                         (reguły Sigma, SQL), alerts (alerty w Sadze), identity, fleet,
                         urd (archiwum), reprocess, svc, throttle, windesc, entrasim
tools/cmd/               siem-pki, siem-ingest-stub, fortisim, entrasim, odczytaj
rules/                   reguły detekcji (windows/, network/, cross/)
deploy/lab/              stos laboratoryjny: docker compose, skrypty, init baz, Grafana,
                         Prometheus, NATS, MSI
deploy/windows/          GPO audytu, instalacja Sysmona
docs/                    dokumentacja
```

Katalogi lokalne poza repozytorium: `bin/` (programy), `certs/` (certyfikaty laboratorium), `dist/` (paczki agentów z kluczami), `data/` (dane testów).
