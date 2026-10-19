# Testy obciążeniowe

Generator `siem-loadgen` udaje tysiące agentów Windows: każdy ma własny certyfikat (wystawiany w pamięci z laboratoryjnego CA), wysyła paczki i heartbeaty tak jak prawdziwy agent 0.7.1 i ma bufor jak dziennik Windows. Serwer nie odróżnia go od floty, więc test sprawdza cały potok: ingest, kolejki, normalizację, zapis, oba silniki detekcji, korelacje i archiwum.

Kod: `server/cmd/siem-loadgen`, `server/internal/loadgen` (szablony zdarzeń).

## Generator

```powershell
go build -o bin/siem-loadgen.exe ./server/cmd/siem-loadgen
bin\siem-loadgen.exe -url https://192.168.88.98:8443/v1/ingest -pki certs -agents 3500 -eps 2 -duration 2h -ramp 60s
```

Uruchamiany z katalogu repozytorium (potrzebuje `certs/ca.crt` i `certs/ca.key`). Ruch generuje stacja, nie serwer, więc generator nie zabiera VM procesora.

| Flaga | Domyślnie | Znaczenie |
|---|---|---|
| `-url` | `https://localhost:8443/v1/ingest` | adres ingestu |
| `-pki` | `certs` | katalog z `ca.crt` i `ca.key` |
| `-agents` | 100 | liczba agentów |
| `-eps` | 5 | zdarzeń na sekundę **na agenta** (ruch całkowity = agents × eps) |
| `-duration` | 2m | czas generowania |
| `-ramp` | 20s | rozruch: agenci startują równomiernie w tym czasie |
| `-batch` | 500 | maksymalna paczka |
| `-flush` | 10s | maksymalny czas zbierania małej paczki (jak agent 0.7.1) |
| `-backlog` | 50000 | bufor agenta; przepełnienie = zdarzenia utracone (jak nadpisany dziennik) |
| `-failures` | 0.2 | udział nieudanych logowań 4625 w % |
| `-heartbeat` | true | heartbeaty co minutę (agenci widoczni w panelu) |
| `-prefix` | `agt-load` | prefiks identyfikatorów agentów |
| `-timeout` | 30s | limit czasu żądania |

**Mieszanka zdarzeń** (Security, System, Application): ok. 40% udanych logowań 4624, 20% wylogowań 4634, 25% procesów 4688, 10% błędów aplikacji, usługi 7036 i 7045. W firmie z 3500 kontami generator ma konta `jkowalski`, `jkowalski2`… Profil zwykłego dnia (`-failures` poniżej 1) kieruje nieudane logowania na 2% kont, każde ze stałego adresu swojego komputera. `-failures 5` to scenariusz ataku: ciągły brute force na wszystkich kontach z losowych adresów (przeciążenie detekcji progowej i korelacji).

**Wynik:** co 10 s linia z ruchem wygenerowanym i przyjętym, paczkami, MB/s, odmowami 429/503, błędami, buforem agentów, utraconymi i opóźnieniem odpowiedzi. Na końcu podsumowanie:

```
zdarzenia: wygenerowane 50607778, przyjęte 50607778, niewysłane (bufor) 0, utracone (przepełnienie bufora) 0
średnio przyjęte: 6956 zdarzeń/s, 2508170 paczek, 6616.9 MB skompresowanych
odmowy: 429 = 7889, 503 = 0; błędy sieci 0, inne 0
opóźnienie odpowiedzi: p50 3ms, p90 9ms, p99 55ms, max 1.175s
```

Test zaliczony: **wygenerowane = przyjęte** i **utracone = 0**. Odmowy 429/503 są dozwolone – agenci ponawiają – ale ich trwały wzrost oznacza, że serwer nie nadąża.

## Przebieg testu

1. **Monitor na VM** (metryki z Prometheusa co 5 min do pliku):

   ```bash
   cd ~/siem-lab && nohup bash loadtest-monitor.sh 300 100 > ~/mon.log 2>&1 < /dev/null &
   ```

   Linia monitora: ruch na etapach (ingest, normalizer, writer, detektor), odmowy, **zaległości konsumentów** (`pending`), zajętość kolejki, opóźnienie p99 od przyjęcia do zapisu, opóźnienie silnika zapytań (`idxlag`), CPU usług i ClickHouse, load, wolne miejsce.
2. **Generator** na stacji (wyżej). Długi test można zabezpieczyć strażnikiem, który zatrzyma generator przy braku miejsca albo rosnącej zaległości.
3. **Grafana:** pulpit „SIEM – zdrowie potoku” (`http://192.168.88.98:3000`).
4. **Ocena:**
   - wszystkie etapy przetwarzają tyle, ile przyjmuje ingest;
   - zaległości konsumentów wahają się, ale **nie rosną w czasie** – to główne kryterium;
   - p99 opóźnienia zapisu w sekundach, nie minutach;
   - silnik zapytań kilka minut w tyle, bez trendu;
   - brak restartów usług (`docker compose ps`) i braku pamięci (`dmesg`, `docker inspect … OOMKilled`).
5. **Po teście:** sprzątanie (niżej). Zaległość detektora z danymi testowymi można pominąć przez założenie konsumenta od nowa (polecenie w sekcji sprzątania).

**Pomiar dziennika zapytań ClickHouse** (co czytało najwięcej w czasie testu):

```sql
SELECT user, normalizeQuery(query) AS q, count() AS n, sum(read_rows) AS rows, formatReadableSize(sum(read_bytes)) AS bytes,
       round(avg(query_duration_ms)) AS ms
FROM system.query_log
WHERE type = 'QueryFinish' AND event_time > now() - INTERVAL 4 HOUR
GROUP BY user, q ORDER BY rows DESC LIMIT 10
```

**Profilowanie:** `SIEM_PPROF=1` w `.env` i `docker compose up -d` włącza `/debug/pprof/` na porcie metryk usług; po teście ustaw `SIEM_PPROF=0`.

## Sprzątanie

Zdarzenia generatora mają `agent_id` z prefiksem `agt-load-` i nie trafiają do archiwum NIS2 (`SIEM_ARCHIVE_EXCLUDE_AGENTS=agt-load-`). Retencja ClickHouse (5 dni w laboratorium) i tak je usunie, ale alerty, stan progów i agenci zostają, więc po teście:

```bash
cd ~/siem-lab
bash loadtest-cleanup.sh            # domyślnie prefiks agt-load-
```

Skrypt usuwa w tej kolejności:

1. zdarzenia w ClickHouse (`events`, `quarantine`, `auth_events`) – najpierw, bo inaczej silnik zapytań odtworzy usunięte alerty z danych, które zostały;
2. przy zatrzymanym detektorze: alerty, stan progów, przypisania i agentów w Sadze;
3. heartbeaty w strumieniu `SIEM_HEARTBEATS` (prawdziwi agenci wyślą kolejny w ciągu minuty).

Skrypt odrzuca prefiksy krótsze niż 5 znaków i sam `agt-` (usunąłby prawdziwych agentów).

**Po dużym teście** (dziesiątki milionów zdarzeń) mutacja `DELETE` w ClickHouse przekracza pamięć. Wtedy najpierw przepisz każdą dzienną partycję z testu – skrypt zachowa prawdziwe zdarzenia, a resztę usunie:

```bash
bash loadtest-droppart.sh 20261017  # partycja = dzień przyjęcia RRRRMMDD
bash loadtest-cleanup.sh
```

**Zaległość detektora z danymi testowymi** (np. setki tysięcy zdarzeń po przeciążeniu) – zamiast czekać, aż ją przerobi, załóż konsumenta od nowa (czyta tylko nowe zdarzenia; zdarzenia z przerwy nadrobi silnik zapytań):

```bash
docker compose stop detector
docker run --rm --network siem_default natsio/nats-box:0.18.1 nats -s nats://nats:4222 consumer rm SIEM_EVENTS detector -f
docker compose start detector
```

## Wyniki (VM 8 vCPU, 9,4 GB RAM)

| Test | Wynik |
|---|---|
| 10 000 zdarzeń/s, kilka minut | stabilnie, p99 3 s, 29% CPU wolne |
| 15 000 zdarzeń/s | VM wysycona, bez strat (9 455 168 / 9 455 168), ok. 9 min nadrabiania |
| 7000/s, 4 h (15.10) | przerwany: od ok. 40 min ClickHouse 3–4 rdzenie, zaległości rosły – przyczyny poprawione (ścieżka awaryjna silnika zapytań, korelacje na tabeli logowań, logi systemowe ClickHouse) |
| 7000/s, 8 h (16/17.10) | 201,8 mln zdarzeń bez strat; zapis i silnik zapytań nadążały; VM na granicy (85–90% CPU), detektor w locie ustępował od 3. godziny |
| 7000/s, 2 h (17.10) | po nadaniu detekcji pierwszeństwa CPU i poprawce korelacji: 50,6 mln bez strat, zaległość detektora 30–340 zdarzeń, **kryterium spełnione** |

Wnioski: na tej VM ok. 5000 zdarzeń/s z zapasem, 7000/s bez narastającej zaległości. Koszt całego stosu to ok. 0,6–1 rdzenia na 1000 zdarzeń/s. ClickHouse zajmuje ok. 125 B na zdarzenie z surowym XML. Szczegóły i historia: [PODSUMOWANIE.md](PODSUMOWANIE.md), zasady skalowania: [ROADMAP.md, załącznik E](ROADMAP.md#załącznik-e-skalowanie-i-przeciążenie).

## Test archiwum

Generator domyślnie omija archiwum. Żeby obciążyć archiwizator, użyj innego prefiksu, np. `-prefix agt-arch`. Zdarzenia z archiwum NIS2 nie są usuwane przed końcem retencji (łańcuch hashy), więc test archiwum wykonuje się świadomie i krótko. Sprzątanie: `bash loadtest-cleanup.sh agt-arch-`.
