# SIEM – własny system SIEM

Projekt według roadmapy [docs/ROADMAP.md](docs/ROADMAP.md) (wersja 1.3).
Obecny stan: **etap 1 ukończony – agent Windows → mTLS → NATS JetStream → normalizator → ClickHouse → Grafana**.

## Struktura

```
cmd/
  siem_agent/          agent Windows (instalator, usługa, konsola)
  siem-ingest-stub/    testowy endpoint /v1/ingest (mTLS → plik NDJSON)
  siem-pki/            certyfikaty laboratoryjne (CA, serwer, agenci)
internal/
  contract/            kontrakt paczki agent → serwer (załącznik A)
  agent/config/        konfiguracja YAML agenta
  agent/core/          paczkowanie, wysyłka, zapis pozycji po potwierdzeniu
  agent/shipper/       HTTPS + mTLS, gzip, ponowienia, 413/400/429/503
  agent/state/         atomowy zapis bookmarków (state.json)
  agent/source/        interfejs źródeł logów
  agent/winevt/        Windows Event Log (wevtapi: subskrypcja + bookmarki)
configs/
  agent.example.yaml   profil domyślny (załącznik B)
  agent.lab.yaml       test bez uprawnień administratora (System, Application)
```

## Szybki start (laboratorium)

```powershell
go build -o bin/ ./cmd/...

# certyfikaty (jednorazowo)
bin\siem-pki.exe ca
bin\siem-pki.exe server -hosts localhost,127.0.0.1
bin\siem-pki.exe agent -id agt-lab-pc01

# terminal 1 – testowy serwer (opcjonalnie -fail-rate 0.3 do testu ponowień)
bin\siem-ingest-stub.exe

# terminal 2 – agent w konsoli
bin\siem_agent.exe -config configs\agent.lab.yaml check
bin\siem_agent.exe -config configs\agent.lab.yaml run
```

Zdarzenia trafiają do `data\events.ndjson`, stan agenta do `data\agent\state.json`.

## Instalacja agenta na komputerze

1. Na stacji administratora przygotuj paczkę dla komputera (certyfikat z
   identyfikatorem agenta, CA, program i domyślny adres serwera):

   ```powershell
   go build -o bin\siem_agent.exe .\cmd\siem_agent
   bin\siem-pki.exe package -id agt-pc01 -server 192.168.88.98
   ```

   Powstaje folder `dist\agt-pc01` (ignorowany przez git – zawiera klucz prywatny).

2. Skopiuj folder na komputer i w PowerShell lub cmd **jako administrator**:

   ```powershell
   .\siem_agent.exe install                       # adres z server.txt albo pytanie o adres
   .\siem_agent.exe install -server 10.0.0.5      # adres podany wprost
   .\siem_agent.exe install -profile dc           # profil zdarzeń: workstation | server | dc
   ```

   Instalator kopiuje program do `C:\Program Files\SiemAgent`, konfigurację
   i certyfikaty do `C:\ProgramData\SiemAgent` (dostęp tylko SYSTEM
   i Administratorzy), sprawdza połączenie z serwerem, rejestruje usługę
   `SiemAgent` (start automatyczny, restart po awarii), uruchamia ją i dodaje
   `C:\Program Files\SiemAgent` do PATH.

3. Sterowanie (nowe okno, z dowolnego folderu):

   | Polecenie | Działanie | Administrator |
   |---|---|---|
   | `siem_agent status` | stan usługi; szczegóły: serwer, kanały, liczniki, limity | szczegóły – tak |
   | `siem_agent start` / `stop` / `restart` | sterowanie usługą | tak |
   | `siem_agent test` | test połączenia z serwerem (TLS + certyfikaty) | tak |
   | `siem_agent set-server <adres>` | zmiana adresu, test, restart agenta | tak |
   | `siem_agent uninstall [-purge]` | odinstalowanie (`-purge`: także dane i certyfikaty) | tak |

Usługa działa jako LocalSystem (dostęp do kanału Security). Log: `C:\ProgramData\SiemAgent\agent.log`.

## Odporność na usunięcie stanu

Pozycje odczytu są zapisywane w `<state_dir>\state.json` oraz (co 30 s) w kopii
w rejestrze `HKLM\SOFTWARE\SiemAgent\Instances\<id>` (agent w konsoli bez
uprawnień: `HKCU`). Kopia jest też znacznikiem, że agent już działał:

| Sytuacja | Zachowanie |
|---|---|
| pierwsze uruchomienie | odczyt zgodnie z `start_at` |
| usunięty / uszkodzony `state.json` | pozycje z kopii w rejestrze – możliwe duplikaty, bez luk |
| usunięty plik i pozycje w kopii (znacznik został) | odczyt od najstarszych zdarzeń dziennika |
| usunięty plik lub katalog w trakcie pracy | odtworzenie w ciągu ~2 s z pamięci |

Każdy z tych przypadków jest zgłaszany jako błąd (log, Podgląd zdarzeń,
`status`). Usunięcie przez administratora zarówno pliku, jak i całego klucza
w rejestrze wygląda dla agenta jak pierwsze uruchomienie – to wykryje dopiero
serwer (heartbeat, etap 2). Odinstalowanie usługi nie usuwa klucza w rejestrze.

## Jak działa gwarancja dostarczania

1. Czytnik subskrybuje kanał Event Log od zapisanego bookmarka (`EvtSubscribe`).
2. Zdarzenia (surowy XML) są pakowane: 500 zdarzeń / 4 MiB / 2 s.
3. Paczka idzie po TLS 1.3 z certyfikatem klienta; `agent_id` = CN certyfikatu.
4. **Pozycja kanału jest zapisywana dopiero po odpowiedzi `accepted`.**
   Awaria w dowolnym momencie = najwyżej ponowne wysłanie (serwer deduplikuje
   po `id`), nigdy luka.
5. Gdy serwer jest niedostępny, wysyłka jest ponawiana z rosnącym opóźnieniem,
   czytniki się zatrzymują, a niewysłane zdarzenia czekają w dzienniku Windows.
6. Spadek numeru rekordu (wyczyszczony dziennik) zwiększa generację w `id`.

Zweryfikowane na tym komputerze: 40 123 / 40 123 zdarzeń System + Application
po twardym zabiciu agenta, 30% odrzuceń 503 i wyłączeniu serwera – bez braków.

## Diagnostyka

```powershell
siem_agent status
```

Pokazuje stan usługi, połączenia z serwerem (ostatnia przyjęta paczka, ostatni
błąd), każdego kanału (OK / BRAK KANAŁU / BRAK DOSTĘPU / BŁĄD, ostatni rekord,
opóźnienie), liczniki, limity, dławienie i zużycie zasobów. Dane pochodzą
z `<state_dir>\status.json`, odświeżanego co 5 s; starszy niż 30 s zapis jest
oznaczany jako nieaktualny (agent zatrzymany lub zawieszony).

W trybie usługi ostrzeżenia i błędy trafiają też do Podglądu zdarzeń
(Dziennik aplikacji, źródło `SiemAgent`, ID 2000 = ostrzeżenie, 3000 = błąd,
1000 = start/zatrzymanie), z tłumieniem powtórzeń przez 10 minut.
Log pliku `<state_dir>\agent.log` jest rotowany w trakcie pracy (`logging`).

## Bezpieczeństwo plików agenta

Uprawnienia `0600` nie działają na Windows – pliki dziedziczą ACL folderu,
a w `C:\ProgramData` zwykli użytkownicy mają prawo odczytu. Agent działający
jako SYSTEM / administrator przy każdym starcie (i instalator usługi) ustawia
na katalogu stanu i kluczu prywatnym chronioną listę dostępu: tylko SYSTEM
i Administratorzy. `siem_agent check` pokazuje, czy klucz i katalog stanu są
chronione. Uruchomiony bez uprawnień administratora agent nie zawęża ACL
(odciąłby sam siebie) i zgłasza to w statusie.

## Zużycie zasobów i limity („kaganiec”)

Sekcja `limits` w `agent.yaml` (przykład w `configs/agent.example.yaml`):
priorytet procesu, twardy limit CPU (Windows Job Object), miękki limit sterty
Go i twardy limit pamięci procesu, limit zdarzeń na sekundę i przepustowości.
Limity nie gubią danych – nadmiar czeka w dzienniku Windows, a agent loguje
ostrzeżenie „agent nie nadąża”, gdy opóźnienie odczytu przekroczy 5 minut.

Pomiary (Ryzen 5 7500F, 12 wątków; odczyt ~40 tys. zdarzeń System + Application,
śr. 1,4 KB; w każdym wariancie dotarł komplet zdarzeń):

| Wariant | Czas odczytu | Uwagi |
|---|---|---|
| bez limitów | ~1,1 s | ~23 µs CPU na zdarzenie; spoczynek ~0% CPU |
| domyślne (below_normal, 150/400 MB) | ~1,1 s | |
| `cpu_max_percent: 5` | ~1,8 s | średnio ≤ 5% komputera; krótkie skoki w obrębie okna Windows |
| `cpu_max_percent: 1` | ~8,6 s | średnio ≤ 1% komputera |
| `max_eps: 5000` | ~6,7 s | zgodnie z oczekiwanym ~7 s |
| `max_send_kbps: 500` | ~16 s | |
| `priority: background`, CPU obciążone w 100% | ~13 s | agent czeka, aż komputer się zwolni |
| `priority: normal`, CPU obciążone w 100% | ~7 s | wpływ agenta na obciążający program ~1% |

Pamięć: working set ~22–26 MB, private bytes ~55–59 MB. Sterta Go to tylko
2–7 MB – resztę stanowią środowisko Go i biblioteki Windows, więc miękki limit
pamięci jest zabezpieczeniem przed nietypowo dużymi zdarzeniami, a nie
sposobem na obniżenie bazowego zużycia.

Od wersji 0.2.0 domyślnie `max_procs: 2`: wątki 22 → 11, uchwyty ~310 → 218,
czas CPU pod pełnym obciążeniem komputera 4,3 s → 3,3 s; odczyt zaległości
bez obciążenia ~1,4 s zamiast ~1,1 s.

## Polityka audytu (dla profilu z załącznika B)

Agent zbiera tylko to, co Windows zapisuje. Minimum w GPO
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
- Sysmon: instalacja z konfiguracją bazową (osobno)

## Testy

```powershell
go vet ./...
go test ./...
```

## Czego jeszcze nie ma (kolejne etapy)

- bufor dyskowy na wypadek nadpisania dziennika podczas długiej przerwy (etap 2)
- rejestracja agenta tokenem, rotacja certyfikatów, konfiguracja z serwera, heartbeat (etap 2)
- instalator MSI (etap 2)
- token deinstalacji i ochrona usługi (etap 8)
- sprawdzanie polityki audytu i synchronizacji czasu (razem z heartbeatem)
- archiwum NIS2 (etap 3), detekcja (etap 4), własny panel (etap 5)

## Serwer laboratoryjny (`deploy/lab`)

```
agent ──mTLS:8443──► siem-ingest ──► NATS SIEM_RAW ──► siem-normalizer ──► NATS SIEM_EVENTS ──► siem-writer ──► ClickHouse ──► Grafana :3000
```

| Usługa | Rola |
|---|---|
| `siem-ingest` | endpoint `/v1/ingest` (mTLS); potwierdza paczkę po zapisie w JetStream (deduplikacja po `batch_id`, okno 10 min) |
| `siem-normalizer` | XML Windows → wspólny schemat (`event.dataset`, `event.action`, użytkownik, IP, proces, pola `fields`); błędne zdarzenia → kwarantanna |
| `siem-writer` | zapis do ClickHouse paczkami (do 20 000 wierszy / 1 s), potwierdzenie z kolejki dopiero po udanym INSERT; wiersz odrzucony przez bazę → kwarantanna, reszta zapisana |
| NATS JetStream | trwała kolejka zaległości (wiadomość znika po przetworzeniu); po zapełnieniu ingest odmawia przyjęcia, nic nie jest usuwane po cichu |
| ClickHouse | `siem.events` (retencja 5 dni od przyjęcia), `siem.quarantine`; konta `siem_writer` (zapis) i `grafana` (odczyt) |
| Grafana | pulpit „SIEM – przegląd zdarzeń” (folder SIEM) |

Wdrożenie (stacja z Windows → VM z Dockerem):

```powershell
# binaria serwera dla Linuksa
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags="-s -w" -o deploy/lab/bin/ ./cmd/siem-ingest ./cmd/siem-normalizer ./cmd/siem-writer
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED

# certyfikat serwera z adresem VM + kopia do stosu (katalog certs jest ignorowany przez git)
bin\siem-pki.exe server -hosts 192.168.88.98,siem,localhost,127.0.0.1
Copy-Item certs\ca.crt, certs\server.crt, certs\server.key deploy\lab\certs\
```

Na VM (katalog `~/siem-lab`): plik `.env` z hasłami według `.env.example`,
`chmod 600 certs/server.key`, następnie `docker compose up -d --build`.
Hasło administratora Grafany: `grep GRAFANA_ADMIN_PASSWORD ~/siem-lab/.env`.

Zweryfikowane: 40 290 zdarzeń z agenta w ClickHouse bez braków i duplikatów,
kompresja ~15× (31,6 MB → 2,1 MB), czas od zdarzenia do zapisu w bazie ~0,8 s,
zatrzymanie ClickHouse – zdarzenia czekają w NATS i są zapisywane po powrocie.

### Skalowanie

Normalizator i writer skaluje się poziomo, dokładając kopie (dzielą pracę z jednej kolejki NATS):

```bash
docker compose up -d --scale normalizer=3 --scale writer=2
```

### Przeciążenie

Gdy agentów jest za dużo naraz albo dalsze etapy nie nadążają, serwer **odkłada przyjęcie**, a nie gubi dane. Dane czekają u agentów.

- Za dużo paczek w obsłudze naraz: `429` z `Retry-After: 5`.
- Kolejka zajęta w 90%: `503` z `Retry-After: 30`.
- Agent czeka co najmniej tyle, ile poda serwer, plus losowe 0–50%.

Ustawienia (w `.env`, wspólne dla usług serwera):

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `SIEM_QUEUE_RAW_MAX_MB` | 8192 | pojemność kolejki surowych paczek |
| `SIEM_QUEUE_EVENTS_MAX_MB` | 8192 | pojemność kolejki znormalizowanych zdarzeń |
| `SIEM_INGEST_MAX_INFLIGHT` | 64 | paczki obsługiwane jednocześnie przez jedną kopię ingest |
| `SIEM_INGEST_QUEUE_HIGH_WATER` | 0.9 | zajętość kolejki, od której ingest odmawia |

Zaległości widać w logach normalizatora i writera: od 50% zajętości ostrzeżenie „kolejka rośnie”. To sygnał, że trzeba dołożyć kopie.

Zasady skalowania, obsługa przeciążenia, pomiary i znane ograniczenia: [docs/ROADMAP.md – załącznik E](docs/ROADMAP.md#załącznik-e-skalowanie-i-przeciążenie).
