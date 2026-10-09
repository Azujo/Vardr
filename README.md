# SIEM – własny system SIEM

Heimdall – własny SIEM według roadmapy [docs/ROADMAP.md](docs/ROADMAP.md) (nazewnictwo: załącznik D).

Obecny stan:

- **ukończone etapy 1 i 1.5:** agent Windows → mTLS → NATS JetStream → normalizator → ClickHouse → Grafana. Potok jest wzmocniony i zmierzony: nadąża przy 10 000 zdarzeń/s;
- **ukończony etap 2 z modułami 1–4 panelu Hliðskjálf:** logowanie i role, agenci (heartbeat, grupy z konfiguracją z serwera), wdrażanie tokenem z własnym CA agentów, wyszukiwarka zdarzeń;
- **w toku:** etap 3 – archiwum NIS2 Urd. Archiwizator z łańcuchem hashy i weryfikacją integralności już działa.

## Struktura

Repozytorium to jeden moduł Go podzielony na części. Kod w `agent/internal/`, `server/internal/` i `panel/internal/` jest prywatny dla swojej części: Go nie pozwala na import z innej części. Wspólne pakiety leżą w `internal/` w katalogu głównym.

```
agent/                     Huginn – agent Windows (działa na komputerach)
  cmd/siem_agent/          program agenta: instalator, usługa, konsola, status
  internal/                config, core (paczkowanie i wysyłka), shipper (HTTPS + mTLS),
                           winevt (Event Log), state, status, limits, logging,
                           logwatch (ochrona przed nadpisaniem dziennika), secure, setup
  configs/                 agent.example.yaml (profil z załącznika B), agent.lab.yaml (test)

server/                    potok zdarzeń (kontenery na serwerze)
  cmd/siem-ingest/         Bifröst: odbiór paczek (mTLS) → NATS
  cmd/siem-normalizer/     Bragi: XML Windows → wspólny schemat
  cmd/siem-writer/         Verðandi: zapis do ClickHouse (Mímir)
  cmd/siem-archiver/       Urd: archiwum NIS2 (oryginalne paczki, łańcuch hashy)
  cmd/siem-loadgen/        generator ruchu: symulacja tysięcy agentów
  internal/                bus (NATS), queue, ingest, normalize, chwriter, model,
                           metrics, archiver, loadgen (szablony zdarzeń)

panel/                     Hliðskjálf – panel zarządzania
  cmd/siem-api/            backend (HTTPS :8444) z wbudowanym frontendem
  internal/api/            API, logowanie i sesje (auth), baza Saga (store, migracje)
  web/                     frontend: React + TypeScript + Mantine

internal/                  wspólne: contract (paczka agent → serwer, załącznik A),
                           svc (konfiguracja, log, ponawianie), throttle, fleet,
                           urd (format archiwum, manifesty, weryfikacja)
tools/                     narzędzia laboratoryjne
  cmd/siem-pki/            certyfikaty (CA, serwer, agenci, paczki instalacyjne)
  cmd/siem-ingest-stub/    testowy endpoint /v1/ingest (mTLS → plik NDJSON)

deploy/lab/                stos serwera: docker compose (NATS, ClickHouse, Saga,
                           Prometheus, Grafana, usługi potoku, panel)
docs/                      roadmapa
```

Katalogi lokalne, poza repozytorium:

- `bin/`: zbudowane programy;
- `certs/`: certyfikaty i klucze laboratorium;
- `dist/`: paczki agentów z kluczami;
- `data/`: dane testów.

## Szybki start (laboratorium)

```powershell
go build -o bin/ ./agent/cmd/... ./tools/cmd/...

# certyfikaty (jednorazowo)
bin\siem-pki.exe ca
bin\siem-pki.exe server -hosts localhost,127.0.0.1
bin\siem-pki.exe agent -id agt-lab-pc01

# terminal 1 – testowy serwer (opcjonalnie -fail-rate 0.3 do testu ponowień)
bin\siem-ingest-stub.exe

# terminal 2 – agent w konsoli
bin\siem_agent.exe -config agent\configs\agent.lab.yaml check
bin\siem_agent.exe -config agent\configs\agent.lab.yaml run
```

Zdarzenia trafiają do `data\events.ndjson`, stan agenta do `data\agent\state.json`.

## Instalacja agenta na komputerze

1. Na stacji administratora przygotuj paczkę dla komputera (certyfikat z
   identyfikatorem agenta, CA, program i domyślny adres serwera):

   ```powershell
   go build -o bin\siem_agent.exe .\agent\cmd\siem_agent
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

### Instalator MSI (od wersji 0.6)

`deploy.sh agent` buduje na serwerze `heimdall-agent.msi` (narzędziem `wixl` w kontenerze, z CA tej instalacji), a panel dołącza go do paczki tokenu (Bifröst) razem z `install-msi.cmd`. Wdrożenie przez Intune, SCCM albo skrypt GPO, jako SYSTEM lub administrator:

```powershell
msiexec /i heimdall-agent.msi /qn SERVER=192.168.88.98 TOKEN=hdt_…   # instalacja i rejestracja tokenem
msiexec /i heimdall-agent.msi /qn                                    # aktualizacja do nowszej wersji (rejestracja zostaje)
msiexec /x heimdall-agent.msi /qn                                    # odinstalowanie (dane i certyfikaty zostają)
```

MSI kopiuje program i CA do `C:\Program Files\SiemAgent`, a potem uruchamia `siem_agent msi-install` (rejestracja tokenem i usługa – ta sama ścieżka co `install`). Nowsza wersja najpierw usuwa starą (bez danych), więc aktualizacja nie zużywa tokenu. Agent zainstalowany wcześniej bez MSI zostaje przejęty: MSI zatrzymuje go, podmienia program i zostawia rejestrację. Token nie trafia do dziennika instalatora. Przebieg kroków agenta: `C:\ProgramData\SiemAgent\msi.log`.

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

Sekcja `limits` w `agent.yaml` (przykład w `agent/configs/agent.example.yaml`):
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

**Gotowy skrypt:** [deploy/windows/heimdall-gpo.ps1](deploy/windows/heimdall-gpo.ps1) – uruchomiony na kontrolerze domeny (administrator domeny) tworzy i podłącza GPO „Heimdall - polityka audytu” (cała domena: zaawansowana polityka inspekcji, linia poleceń w 4688, logowanie bloków PowerShell, dziennik Security 256 MB) oraz „Heimdall - dzienniki DC” (Security 1 GB na kontrolerach domeny). Można go uruchamiać wielokrotnie. Sprawdzony w laboratorium (Windows Server 2025, Windows 11): nieudane logowania (4625, 4776, 4768), zmiany kont i grup (4720, 4732, 4733, 4726), procesy z linią poleceń (4688) i PowerShell (4104) docierają do Mímira.

**Sysmon:** [deploy/windows/sysmon.ps1](deploy/windows/sysmon.ps1) instaluje albo aktualizuje Sysmona (program z podpisem Microsoftu, konfiguracja domyślnie SwiftOnSecurity albo z udziału `-Source \\domena\NETLOGON\sysmon`). Nadaje się na skrypt startowy komputera w GPO i można go uruchamiać wielokrotnie. Agent (od 0.6.2) niczego nie instaluje – raportuje stan Sysmona (wersja, skrót konfiguracji), a w grupie agentów z opcją „Wymagany Sysmon” panel zgłasza komputery bez Sysmona, z zatrzymanym Sysmonem albo z inną konfiguracją niż większość grupy.

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

## Bufor dyskowy agenta (od wersji 0.6)

Paczka, której nie udało się wysłać od razu (brak sieci, serwer przeciążony), trafia do `C:\ProgramData\SiemAgent\buffer` (zapis z `fsync`), a agent zapisuje pozycję odczytu i czyta dalej. Osobny wątek dosyła paczki z dysku, najstarsze najpierw. Długa przerwa w łączności nie zależy więc już od rozmiaru dziennika Windows.

- **Limit:** domyślnie 1024 MB (`buffer.max_mb` w `agent.yaml` albo „Bufor dyskowy” w grupie agentów w panelu; 0 = wyłączony). Bufor nigdy nie zabiera ostatniego 1 GB wolnego miejsca (`buffer.min_free_mb`).
- **Po zapełnieniu** (`buffer.on_full` albo grupa w panelu): `pause` (domyślnie) – nowe zdarzenia czekają w dzienniku Windows jak bez bufora; `drop_oldest` – usuwane są najstarsze paczki z bufora, a liczba utraconych zdarzeń trafia do statusu i panelu.
- Stan bufora widać w `siem_agent status` i w panelu (Huginn → agent). Panel zgłasza problem, gdy paczki czekają dłużej niż 5 minut, gdy bufor jest pełny i gdy coś utracono.

**Zegar:** agent przy każdym heartbeacie mierzy odchylenie swojego zegara od serwera (nagłówek `X-Heimdall-Time`) i co 5 minut sprawdza usługę czasu Windows (W32Time). Panel zgłasza odchylenie ponad 60 s i wyłączoną usługę czasu (zatrzymana jest normalna poza domeną – Windows uruchamia ją na żądanie).

## Rozmiar dzienników Windows

Bez bufora dyskowego (agent starszy niż 0.6 albo bufor wyłączony lub pełny w trybie `pause`) buforem jest dziennik Windows. Gdy serwer jest niedostępny, niewysłane zdarzenia czekają w dzienniku, a po jego zapełnieniu Windows nadpisuje najstarsze. Domyślne 20 MB to przy typowym ruchu:

- na stacji: kilka godzin zapasu;
- na obciążonym serwerze lub kontrolerze domeny: kilkanaście sekund do kilku minut.

Zalecane rozmiary (GPO: *Computer Configuration → Policies → Administrative Templates → Windows Components → Event Log Service → <dziennik> → Specify the maximum log file size (KB)*, z zachowaniem nadpisywania najstarszych wpisów):

| Dziennik | Stacje robocze | Serwery | Kontrolery domeny |
|---|---|---|---|
| Security | 128–256 MB | 512 MB–1 GB | 1–4 GB |
| System, Application | 64 MB | 128 MB | 128 MB |
| PowerShell/Operational, Sysmon | 64 MB | 256 MB | 256 MB |

Jednorazowo na pojedynczej maszynie (administrator): `wevtutil sl Security /ms:1073741824`.

Agent pilnuje tego sam:

- **co minutę** sprawdza, jaką część dziennika zajmują zdarzenia jeszcze niewysłane. Od 50% zgłasza ostrzeżenie, od 80% alarm, oba z szacowanym czasem do nadpisania przy obecnym tempie;
- **przy wznowieniu** (np. po długim wyłączeniu) i w trakcie pracy zgłasza dokładny zakres rekordów nadpisanych przed odczytem („LUKA W DANYCH”);
- **przy starcie** podpowiada zwiększenie dziennika Security mniejszego niż 128 MB i ostrzega przed ustawieniem „nie nadpisuj”, przy którym Windows po zapełnieniu przestaje zapisywać nowe zdarzenia.

Wszystkie te komunikaty trafiają do logu agenta, do `siem_agent status` i (gdy agent działa jako usługa) do Podglądu zdarzeń (Application, źródło `SiemAgent`).

## Testy

```powershell
go vet ./...
go test ./...
```

Na GitHubie testy uruchamiają się automatycznie przy każdym pushu ([.github/workflows/ci.yml](.github/workflows/ci.yml)):

- **Linux:** `gofmt`, `go vet`, testy z wykrywaniem wyścigów (`-race`), 60 s fuzzingu parsera XML i budowanie usług serwera;
- **Windows:** `go vet`, testy agenta i budowanie `siem_agent.exe`.

Wynik widać w zakładce *Actions* repozytorium.

## Czego jeszcze nie ma (kolejne etapy)

- token deinstalacji i ochrona usługi (etap 8)
- sprawdzanie polityki audytu (razem z heartbeatem)
- detekcja (etap 4), alerty i reguły w panelu (etap 5)

Podsumowanie etapów i lista znanych luk: [docs/PODSUMOWANIE.md](docs/PODSUMOWANIE.md).

## Serwer laboratoryjny (`deploy/lab`)

```
agent ──mTLS:8443──► siem-ingest ──► NATS SIEM_RAW ──► siem-normalizer ──► NATS SIEM_EVENTS ──► siem-writer ──► ClickHouse ──► Grafana :3000
                                                   └──► siem-archiver ──► ./archive (segmenty + manifesty), spis w Sadze
```

| Usługa | Rola |
|---|---|
| `siem-ingest` | endpoint `/v1/ingest` (mTLS); potwierdza paczkę po zapisie w JetStream (deduplikacja po `batch_id`, okno 10 min) |
| `siem-normalizer` | XML Windows → wspólny schemat (`event.dataset`, `event.action`, użytkownik, IP, proces, pola `fields`); błędne zdarzenia → kwarantanna |
| `siem-writer` | zapis do ClickHouse paczkami (do 20 000 wierszy / 1 s), potwierdzenie z kolejki dopiero po udanym INSERT; wiersz odrzucony przez bazę → kwarantanna, reszta zapisana |
| `siem-archiver` | Urd – archiwum NIS2: oryginalne paczki w segmentach na dysku, godzinowe manifesty z łańcuchem hashy, weryfikacja integralności, eksport dla audytora, odtwarzanie (replay) |
| `normalizer-replay`, `writer-replay` | kopie normalizatora i writera dla paczek odtwarzanych z archiwum → `siem.events_replay` |
| NATS JetStream | trwała kolejka zaległości (wiadomość znika po przetworzeniu); po zapełnieniu ingest odmawia przyjęcia, nic nie jest usuwane po cichu |
| ClickHouse | `siem.events` (retencja 5 dni od przyjęcia), `siem.quarantine`; konta `siem_writer` (zapis) i `grafana` (odczyt) |
| Grafana | pulpit „SIEM – przegląd zdarzeń” (folder SIEM) |
| node-exporter | metryki systemu VM dla Prometheusa: miejsce na dyskach, CPU, pamięć |

Wdrożenie ze stacji (Git Bash) na VM: jeden skrypt kopiuje konfigurację stosu, buduje programy dla Linuksa z wersją z gita (`git describe`, widoczna w logu „start” i w panelu), kopiuje je i restartuje usługi:

```bash
deploy/lab/deploy.sh                    # konfiguracja + wszystkie usługi
deploy/lab/deploy.sh web api            # frontend panelu i siem-api
deploy/lab/deploy.sh archiver agent     # wybrane cele (agent = siem_agent.exe do paczek)
```

Skrypt nie dotyka `certs/`, `.env` ani danych. Certyfikat serwera z adresem VM przygotowuje się raz na stacji i kopiuje do `~/siem-lab/certs` (katalog `certs` jest ignorowany przez git):

```powershell
bin\siem-pki.exe server -hosts 192.168.88.98,siem,localhost,127.0.0.1
```

Na VM (katalog `~/siem-lab`): plik `.env` z hasłami według `.env.example`,
`chmod 600 certs/server.key`, następnie `docker compose up -d --build`.
Hasło administratora Grafany: `grep GRAFANA_ADMIN_PASSWORD ~/siem-lab/.env`.

Retencję ustawia się w `.env`:

- `SIEM_EVENTS_TTL_DAYS`: zdarzenia i kwarantanna, domyślnie 5 dni;
- `SIEM_RAW_TTL_DAYS`: surowy XML, domyślnie 5 dni. Po tym czasie zostają pola znormalizowane, a XML to ok. 40–50% miejsca w bazie.

Zmiany na działającej bazie stosuje skrypt `./clickhouse/retention.sh`, uruchamiany na VM w katalogu stosu. Wypisuje też, ile miejsca zajmują największe kolumny. W laboratorium surowy XML jest trzymany 2 dni (zdarzenia 5 dni): oryginały są w archiwum Urd, więc starszy XML da się odtworzyć (replay) albo wyeksportować. Wyjątek: agenci wyłączeni z archiwum polityką tracą XML po 2 dniach bezpowrotnie.

Zweryfikowane: 40 290 zdarzeń z agenta w ClickHouse bez braków i duplikatów,
kompresja ~15× (31,6 MB → 2,1 MB), czas od zdarzenia do zapisu w bazie ~0,8 s,
zatrzymanie ClickHouse – zdarzenia czekają w NATS i są zapisywane po powrocie.

### Panel Hliðskjálf (siem-api)

Panel działa pod adresem **https://192.168.88.98:8444**. Korzysta z certyfikatu serwera z laboratoryjnego CA i bazy Saga (PostgreSQL, usługa `saga`).

**Pierwsze uruchomienie:**

1. Na VM, w `~/siem-lab`, załóż pierwsze konto administratora. Hasło startowe pojawi się tylko na ekranie i trzeba je zmienić przy pierwszym logowaniu:

   ```bash
   docker compose run --rm api bootstrap-admin -username admin
   ```

2. Na stacji, żeby przeglądarka ufała certyfikatowi panelu, dodaj laboratoryjne CA do zaufanych głównych urzędów **swojego konta** (bez uprawnień administratora):

   ```powershell
   certutil -user -addstore Root certs\ca.crt
   ```

   Windows zapyta o potwierdzenie. Usunięcie: `certutil -user -delstore Root "SIEM Lab CA"`.

**Huginn – agenci:** agent (od wersji 0.4.0) co minutę wysyła heartbeat ze swoim stanem, czyli tym samym, co pokazuje `siem_agent status`. Trasa: `POST /v1/heartbeat` na siem-ingest (mTLS) → strumień NATS `SIEM_HEARTBEATS` (ostatni heartbeat na agenta) → siem-api → tabela `agents` w Sadze.

Panel pokazuje dla każdego agenta:

- stan online lub offline (offline po 3 minutach bez heartbeatu);
- wersję, system, adres IP i ważność certyfikatu;
- kanały, liczniki zdarzeń, zużycie zasobów i ostrzeżenia;
- czytelną listę problemów, np. „kanał Security: brak dostępu”, „certyfikat wygasa za 5 dni”, „wysyłka zdarzeń nieudana”.

Agenci ze starszych wersji wysyłają zdarzenia, ale nie pojawiają się na liście, dopóki nie zostaną zaktualizowani. Generator ruchu też wysyła heartbeaty (`-heartbeat`, domyślnie włączone), więc listę da się sprawdzić na tysiącach agentów.

**Bifröst – wdrażanie agentów tokenem:** administrator tworzy w panelu token rejestracyjny: nazwa, profil zdarzeń, ważność i limit instalacji. Token jest widoczny raz, a w bazie zostaje tylko jego skrót. Do tokenu panel daje paczkę ZIP (program agenta, główne CA, adres serwera, token, `install.cmd`) **bez klucza prywatnego** i gotowe polecenie do GPO lub Intune:

```bash
siem_agent.exe install -server 192.168.88.98 -token hdt_…
```

Przebieg instalacji:

1. Agent generuje klucz na komputerze. Klucz nigdy go nie opuszcza.
2. Agent wysyła prośbę o certyfikat (CSR) z tokenem do panelu (`POST /enroll/v1/register`, port 8444).
3. Panel nadaje identyfikator z nazwy hosta. Zajęty identyfikator dostaje dopisek, więc nikt nie przejmie cudzej tożsamości.
4. Panel wydaje certyfikat na 90 dni, a agent odnawia go sam na 30 dni przed końcem (`/enroll/v1/renew`, z nowym kluczem).

Certyfikaty podpisuje osobne **CA agentów** (`siem-pki agents-ca`), które może wystawiać wyłącznie certyfikaty klientów. Główne CA zostaje offline, a agenci sprawdzają nim serwer.

**Unieważnianie:** w panelu (Huginn → agent → „Unieważnij certyfikat”). Panel zapisuje unieważnienie w NATS (`SIEM_REVOKED_CERTS`), a ingest odrzuca taki certyfikat przy nawiązywaniu połączenia.

Inne polecenia agenta:

- `siem_agent enroll -server … -token … -dir …`: rejestracja bez instalowania usługi, np. do testów;
- `siem_agent upgrade`: aktualizacja programu z folderu nowej wersji, z zachowaniem konfiguracji, certyfikatów i stanu.

Przygotowanie serwera:

- `binsiem-pki.exe agents-ca`, potem `agents-ca.crt` i `agents-ca.key` do `~/siem-lab/certs`;
- `siem_agent.exe` do `~/siem-lab/agent-dist`;
- w `.env`: `SIEM_PUBLIC_SERVER=192.168.88.98`.

**Mímir – wyszukiwarka zdarzeń:** zapytania w prostym języku, np.:

```
code:4625 user:jkowalski
host:pc0* -action:logged-out
"invoke-expression" powershell
fields.TargetUserName:admin ip:10.0.5.23
```

Prefiksy pól filtrują, `*` na końcu oznacza prefiks, `-` neguje warunek, a pozostałe słowa i frazy w cudzysłowach są wyszukiwane w treści zdarzenia (opis i surowy XML). Lista pól jest pod ikoną „?” w panelu.

Na stronie są:

- histogram, w którym kliknięcie słupka zawęża zakres czasu;
- wyniki ze stronicowaniem; kliknięcie wartości w tabeli dodaje filtr;
- szczegóły zdarzenia: wszystkie pola (z filtrem po wartości) i sformatowany surowy XML.

Stan wyszukiwania jest zapisany w adresie strony, więc wynik można wysłać jako link.

Panel łączy się z ClickHouse kontem `siem_panel`, które ma tylko prawo odczytu oraz limity czasu i rozmiaru wyniku po stronie bazy. Wartości z zapytania trafiają do SQL wyłącznie jako parametry. Na istniejącej instalacji konto zakłada się raz (instrukcja w `clickhouse/init/01-schema.sh`), a hasło trafia do `CLICKHOUSE_PANEL_PASSWORD` w `.env`.

**Grupy agentów – konfiguracja z serwera:** grupa określa profil zdarzeń (stacja, serwer, kontroler domeny) i limity zasobów (CPU, pamięć, zdarzenia/s, łącze, priorytet). Agent od wersji 0.5.0:

- co 5 minut pobiera konfigurację swojej grupy z panelu (`GET /enroll/v1/config`, mTLS, ETag);
- stosuje ją **bez restartu usługi**: przeładowuje odczyt kanałów i aktualizuje limity w Job Object;
- zapisuje ostatnią konfigurację lokalnie (`managed.json` w katalogu stanu), więc działa na niej także przy niedostępnym panelu.

Lokalny `agent.yaml` dalej decyduje o adresie serwera i certyfikatach. Agent bez przypisania należy do grupy „Domyślna”. Token rejestracyjny wskazuje grupę dla nowych agentów.

Panel pokazuje przy agencie, czy jego konfiguracja jest aktualna (wersja z heartbeatu porównana z wersją grupy). `siem_agent status` pokazuje źródło konfiguracji. Zmienna `SIEM_CONFIG_POLL_SECONDS` przyspiesza pobieranie (diagnostyka).

**Zapomniane hasło administratora:** `docker compose run --rm api reset-password -username admin`.

**Bezpieczeństwo:**

- hasła hashowane algorytmem argon2id, minimum 12 znaków;
- blokada konta na 15 min po 10 nieudanych logowaniach, do tego limit prób z jednego adresu;
- sesja w ciasteczku `__Host-` (`HttpOnly`, `Secure`, `SameSite=Strict`) i token CSRF;
- sesja wygasa po 1 h bezczynności, najpóźniej po 8 h;
- zmiana hasła lub roli kończy pozostałe sesje konta;
- nagłówki CSP, HSTS i `X-Frame-Options`;
- każde logowanie i zmiana trafia do dziennika audytu.

Role:

- **administrator:** wszystko, w tym konta;
- **analityk:** praca z danymi;
- **tylko odczyt.**

**Frontend** (React, TypeScript, Mantine) leży w `panel/web/`, a jego build jest wbudowany w program `siem-api`. Wymaga Node.js LTS:

```powershell
cd panelweb
npm ci
npm run build    # panel/web/dist → wbudowywane przy budowaniu siem-api
npm run dev      # podgląd na żywo: http://localhost:5173, API przekierowane do VM
```

Bez zbudowanego frontendu `siem-api` działa dalej, tylko zamiast panelu pokazuje stronę z instrukcją.

### Detekcja – Gjallarhorn (siem-detector)

Reguły w formacie **Sigma (YAML)** leżą w repozytorium w katalogu [rules/](rules/) i trafiają na serwer poleceniem `deploy/lab/deploy.sh rules` (najpierw są sprawdzane: `go run ./server/cmd/siem-detector check rules`). Detektor przeładowuje je w ciągu 30 s bez restartu.

- **Silnik w locie:** `siem-detector` to osobny odbiorca strumienia zdarzeń `SIEM_EVENTS`; ocenia każde zdarzenie wszystkimi włączonymi regułami. Zatrzymany detektor powoduje zator (nie pomija zdarzeń); `siem-detector disable` usuwa jego konsumenta.
- **Silnik zapytań** (profil pełny): reguły kompilowane do SQL i wykonywane co minutę na `siem.events` w ClickHouse (konto `siem_detector` tylko do odczytu, z limitami). Każdy przebieg ocenia zdarzenia **przyjęte** od punktu kontrolnego (w Sadze, zapisywany razem z alertami) do „teraz − 2 min”, z 5-minutową zakładką – więc łapie też zdarzenia spóźnione z bufora agenta. Wszystkie reguły w jednym zapytaniu; dla progów drugie zapytanie dociąga kontekst kluczy, a okna liczy ten sam kod co silnik w locie.
- **Wybór silników:** `SIEM_DETECTION_MODE` = `stream` (profil wydajnościowy), `index_query` (pełny – konsument strumienia jest wtedy usuwany) albo `both` (laboratorium). Przy `both` alerty się nie dublują – para (reguła, zdarzenie) trafia do alertu raz, a pole „Silnik” w alercie mówi, który ją znalazł. Parametry: `SIEM_INDEX_INTERVAL` (1m), `SIEM_INDEX_DELAY` (2m), `SIEM_INDEX_OVERLAP` (5m), `SIEM_INDEX_LOOKBACK` (1h, pierwszy start).
- **Zgodność silników** sprawdza test na prawdziwym ClickHouse (w CI przy każdym pushu): ten sam korpus zdarzeń i reguły z `rules/` oraz `server/internal/detector/testdata/compat` (wszystkie modyfikatory) muszą dać te same dopasowania w Go i w SQL i te same trafienia progów, niezależnie od kolejności napływu. Znane różnice: słowa kluczowe przeszukują surowy XML, który w ClickHouse żyje krócej (`SIEM_RAW_TTL_DAYS`); czas zdarzenia w ClickHouse ma dokładność milisekund.
- **Alerty** zapisuje w Sadze (schemat `gjallarhorn`, rola `siem_detector`). Para (reguła, zdarzenie) trafia do alertu najwyżej raz, więc ponowne dostarczenie i restart nie dublują alertów. Reguła z `heimdall.group_by` łączy trafienia z tymi samymi wartościami pól w oknie `heimdall.suppress` (domyślnie 1 h) w jeden alert z licznikiem.
- **Powiadomienia:** alert i wpis w outboxie powstają w jednej transakcji; panel wysyła je na kanały z zaznaczonym „alerty detekcji” (Powiadomienia), z ponawianiem (najwyżej 30 prób, ok. doby). Każdy kanał ma **filtr alertów**: od jakiego poziomu i z których reguł (wszystkie / tylko wybrane / wszystkie poza wybranymi) – np. Discord tylko „wysoki” i „krytyczny”, a webhook do systemu zgłoszeń wszystko. Zawężenie filtru wymaga ponownego podania hasła (jak wyłączenie kanału). Wartości ze zdarzeń są w Discordzie escapowane (atakujący nie podsunie linku w treści polecenia).
- **Utrata i powrót agenta:** w grupie agentów „Alarm po utracie łączności” (próg) i „Powiadamiaj także o powrocie” – wtedy po powrocie agenta przychodzi wiadomość „[ROZWIĄZANY]” z długością przerwy (przez te same kanały i filtry).
- **Samokontrola detektora:** gdy pętla detekcji nie robi postępu przez 3 min (silnik zapytań – 15 min), proces kończy się sam, Docker uruchamia go ponownie, a stan progów wraca z Sagi.
- **Panel:** *Gjallarhorn* i *Reguły detekcji* (treść, otwarte alerty, błędy wczytania). Praca z alertami (etap 5a):
  - lista z filtrami (stan, poziom „od”, przypisany – „moje” / „nieprzypisane”, czas ostatniego zdarzenia, silnik, komputer, konto, tekst), licznikiem i doładowywaniem starszych; kliknięcie komputera albo konta filtruje listę;
  - zaznaczanie wielu alertów: „Weź do analizy”, „Zamknij” (jeden powód dla wszystkich), „Otwórz ponownie”;
  - szczegóły: przypisanie analityka („Biorę do analizy” przypisuje do siebie), oś czasu (zmiany stanu, przypisania, notatki – także automatyczne zamknięcia przez system), notatki, powiązane alerty (ten sam komputer albo konto, ±24 h), przycisk „zdarzenia z tego komputera ±15 min” w Mímirze;
  - każda zmiana trafia na oś czasu alertu i do audytu panelu; przypisać można tylko aktywnego analityka albo administratora.
- **Obsługiwany podzbiór Sigmy:** `logsource` Windows (service: security, system, application, sysmon, powershell…; category: process_creation – Sysmon 1 i Security 4688, ps_script, network_connection, file_event, dns_query, registry_set), selekcje (mapy, listy, słowa kluczowe), modyfikatory `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `exists`, maski `*`/`?`, warunki `and/or/not`, `1 of`/`all of`. Reszta (agregacje `| count()`, `timeframe`, inne modyfikatory) jest jawnie odrzucana – progi definiuje się rozszerzeniem `heimdall.threshold`.
- **Rozszerzenia Heimdalla** (klucz `heimdall:` w regule): `mode` (stream / index_query / both), `group_by`, `suppress`, `instructions` (pokazywane w alercie i na Discordzie; zmienne `{{Pole}}`, np. `{{SubjectUserName}}`, `{{Computer}}`, są zastępowane wartościami ze zdarzenia przy tworzeniu alertu), `enabled`, `threshold`.
- **Reguły progowe** (`heimdall.threshold`: `count`, `window`, opcjonalnie `distinct`): alert powstaje, gdy w dowolnym oknie `window` (liczonym po czasie zdarzenia, więc spóźnione zdarzenia z bufora agenta też się liczą) jest co najmniej `count` pasujących zdarzeń – albo `count` różnych wartości pola `distinct` – z tym samym kluczem `group_by`. Do alertu trafiają wszystkie zdarzenia z tego okna oraz – łańcuchowo – kolejne (i wcześniejsze) zdarzenia tego klucza, dopóki przerwa nie przekroczy `suppress` (co najmniej długość okna); zdarzenia już będące w alercie przedłużają łańcuch, nawet gdy samo okno wypadło z pamięci. W instrukcji działają dodatkowo `{{count}}`, `{{window}}` i `{{values}}` (lista różnych wartości). Stan progów jest zapisywany razem z alertami (`gjallarhorn.threshold_events`), więc restart detektora nie zeruje liczników. Silnik w locie trzyma zdarzenia klucza z okna + max(`suppress`, 1 h); zdarzenie spóźnione bardziej liczy się tylko z tym, co zostało w pamięci – takie przypadki nadrabia silnik zapytań. Przykłady: [brute force](rules/windows/security_brute_force_logon.yml), [password spraying](rules/windows/security_password_spraying.yml).
- **Utrata łączności z agentem** (reguła wbudowana, nie Sigma): detektor co 30 s porównuje ostatni heartbeat agentów z progiem ich grupy – panel → *Grupy agentów* → „Alarm po utracie łączności” (5–10 080 min; puste = bez alarmu, np. stacje wyłączane na noc). Jedna przerwa = jeden alert (`engine = system`); gdy agent wróci, alert zamyka się sam z adnotacją. Agenci wycofani (wszystkie certyfikaty unieważnione) są pomijani. Uzupełnia ją reguła Sigma na zatrzymanie usługi agenta albo Sysmona (System 7036/7031/7034) – zdarzenie dociera po ponownym starcie agenta i mówi, kiedy dokładnie usługę zatrzymano.
- **Reguły w repozytorium (scenariusze z roadmapy, sekcja 11):** brute force (4625, Kerberos 4771), password spraying, dodanie do grupy uprzywilejowanej, wyczyszczenie dziennika Security (1102) i innych dzienników (System 104), PowerShell z zakodowanym poleceniem i podejrzane skrypty (4104), usługa z podejrzanej lokalizacji (7045), nowe konto (4720), zatrzymanie usług bezpieczeństwa, utrata łączności z agentem. Scenariusze FortiGate (VPN) i Entra ID czekają na te integracje.

### Archiwum NIS2 – Urd (siem-archiver)

Archiwizator zapisuje **oryginalne paczki agentów** (przed normalizacją, skompresowane tak, jak przyszły) w katalogu `~/siem-lab/archive`. Jest osobnym odbiorcą kolejki `SIEM_RAW`, więc paczka znika z kolejki dopiero wtedy, gdy zapiszą ją oba etapy: normalizator i archiwum.

- **Segmenty:** paczki są dopisywane do pliku segmentu, zamykanego po 30 s albo 64 MB. Plik dostaje `fsync`, prawa tylko do odczytu i wpis w spisie (baza Saga, schemat `urd`). Dopiero wtedy paczki są potwierdzane w kolejce. Po awarii niezatwierdzony segment jest usuwany, a jego paczki przychodzą ponownie.
- **Manifesty i łańcuch hashy:** po każdej pełnej godzinie powstaje manifest z listą segmentów i ich sumami SHA-256 oraz hashem poprzedniego manifestu. Manifest trafia na dysk i do bazy. Manifest dostaje też godzina bez danych, więc brakującą godzinę da się wykryć.
- **Weryfikacja** (co 6 h i 2 min po starcie) w każdym przebiegu sprawdza całe archiwum tanimi metodami:
  - ciągłość łańcucha;
  - zgodność manifestów w bazie i na dysku;
  - obecność i rozmiar każdego segmentu, więc usunięcie lub ucięcie wychodzi od razu;
  - pliki dodane poza archiwizatorem;
  - przerwę w tworzeniu manifestów.

  Pełne sprawdzenie treści (SHA-256 segmentu i każdej paczki) obejmuje w jednym przebiegu najwyżej `SIEM_ARCHIVE_VERIFY_BUDGET_GB`, domyślnie 50 GB:
  - najpierw manifesty jeszcze niesprawdzone, czyli nowe oraz te z wykrytym problemem;
  - potem sprawdzone najdawniej.

  Kolejne przebiegi obejmują więc całe archiwum po kolei. Manifest z problemem nie dostaje znacznika sprawdzenia, więc niezgodność nie znika z widoku. Panel pokazuje, od kiedy całość jest sprawdzona w całości. `verify --full` czyta całe archiwum, np. przed audytem. Wynik trafia do bazy, do logu i do metryk `siem_archive_verify_ok` i `siem_archive_verify_problems`.
- **Retencja:** ustawiana w polityce w panelu (niżej), przy pierwszym starcie `SIEM_ARCHIVE_RETENTION_DAYS` z `.env`, domyślnie 30 dni. Dane starszych godzin są usuwane, a wpisy manifestów zostają w bazie, więc łańcuch pozostaje ciągły.
- **Miejsce na dysku:** archiwum zajmuje ok. 100 B na zdarzenie, czyli ~85 GB na dobę przy 10 000 zdarzeń/s. Powinno więc leżeć na osobnym dysku: `SIEM_ARCHIVE_PATH` w `.env`, np. `/srv/heimdall/archive`.
  - Poniżej 15% wolnego miejsca archiwizator ostrzega.
  - Poniżej 5% albo 2 GB wstrzymuje archiwizację (`SIEM_ARCHIVE_MIN_FREE_PERCENT`, `SIEM_ARCHIVE_MIN_FREE_GB`). Paczki czekają wtedy w kolejce, zamiast zapełnić dysk.
  - Stan dysku jest widoczny w panelu i w metrykach `siem_archive_disk_free_bytes` i `siem_archive_paused`.
- **Agenci zawsze wyłączeni:** paczki agentów o prefiksach z `SIEM_ARCHIVE_EXCLUDE_AGENTS` nie trafiają do archiwum niezależnie od polityki. Domyślnie dotyczy to `agt-load-`, czyli generatora ruchu. Pusta wartość archiwizuje wszystko, np. do testu wydajności archiwum.

W panelu stan archiwum widać w module **Urd**:

- stan zgodności: zgodne, niezgodności z listą problemów, archiwizator nie działa, weryfikacja nieaktualna;
- rozmiar i zakres danych oraz retencję;
- łańcuch manifestów z hashami i oznaczeniem zerwanego ogniwa;
- historię weryfikacji.

- politykę archiwum ze źródłami bez archiwizacji i historią zmian (zakładka *Polityka*).

Administrator może zlecić weryfikację przyciskiem „Zweryfikuj teraz”. Archiwizator rozpoczyna ją w ciągu minuty, a zlecenie trafia do audytu. Kafelek z tym stanem jest też na stronie startowej.

**Dysk archiwum (jednorazowo, wymaga sudo):** w laboratorium to osobny dysk 150 GB (`/dev/sdb`) zamontowany w `/srv/heimdall`, z katalogami `archive` i `backup` należącymi do `siem` (uid 1000):

```bash
sudo mkfs.ext4 -L heimdall-data /dev/sdb
sudo mkdir -p /srv/heimdall && echo 'LABEL=heimdall-data /srv/heimdall ext4 defaults,noatime,nofail 0 2' | sudo tee -a /etc/fstab && sudo mount -a
sudo mkdir -p /srv/heimdall/archive /srv/heimdall/backup && sudo chown -R 1000:1000 /srv/heimdall && sudo chmod 750 /srv/heimdall/archive /srv/heimdall/backup
```

W `.env` ustaw `SIEM_ARCHIVE_PATH=/srv/heimdall/archive`. Dzięki `nofail` brak dysku nie blokuje startu VM, a dwie blokady chronią przed pisaniem archiwum na dysk systemowy:

- Docker nie zakłada brakującego katalogu (`create_host_path: false`), więc archiwizator nie wystartuje;
- archiwizator odmawia pracy, gdy spis w bazie ma manifesty, a katalog nie zawiera archiwum (znacznik `.urd-archive`).

**Polityka archiwum (panel, *Urd → Polityka*).** Administrator ustawia:

- czy nowe paczki są archiwizowane;
- retencję w dniach;
- grupy agentów i pojedynczych agentów wyłączonych z archiwum. Nowy agent w wyłączonej grupie też nie jest archiwizowany.

Panel tylko składa zlecenie zmiany. Rozpatruje je archiwizator, w ciągu minuty, według zasad z konfiguracji serwera, których panel nie zmieni:

- **wzmocnienie** (włączenie, dłuższa retencja, objęcie archiwum kolejnych źródeł) działa od razu;
- **osłabienie** (wyłączenie, krótsza retencja, wyłączenie źródła) wymaga ponownego podania hasła i powodu. Wchodzi w życie dopiero po karencji `SIEM_ARCHIVE_POLICY_GRACE`, domyślnie 24 h. Do tego czasu panel i alert w Grafanie pokazują je jako zaplanowane, a administrator może je anulować;
- retencja musi mieścić się w granicach `SIEM_ARCHIVE_MIN_RETENTION_DAYS`–`SIEM_ARCHIVE_MAX_RETENTION_DAYS` (domyślnie 30–3650 dni). Archiwizator nigdy nie usuwa danych przed minimum, nawet gdyby ktoś zapisał w bazie krótszą retencję;
- wyłączenie dotyczy tylko **nowych** paczek; zarchiwizowane dane zostają do końca retencji, a manifesty powstają dalej (także puste), więc przerwa jest widoczna w łańcuchu.

Każde zlecenie, anulowanie i nieudane potwierdzenie hasłem trafia do audytu, a błędne hasło liczy się do blokady konta jak przy logowaniu. Stan zgodności pokazuje „archiwizacja WYŁĄCZONA” i „zaplanowane osłabienie polityki”, a Grafana ma alerty `heimdall-archive-disabled` i `heimdall-archive-policy-scheduled`. Metryki: `siem_archive_policy_enabled`, `siem_archive_policy_scheduled_weakening`, `siem_archive_policy_retention_days`, `siem_archive_skipped_total{reason}`.

Rola panelu w bazie może tylko złożyć zlecenie i je anulować; nie zmieni obowiązującej polityki ani stanu zlecenia. Archiwizator czyta z tabel panelu wyłącznie przypisania agentów do grup.

```bash
docker compose exec archiver /app verify          # weryfikacja na żądanie, w ramach budżetu (kod wyjścia 1 = niezgodności)
docker compose exec archiver /app verify --full   # całe archiwum odczytane w całości
docker compose exec archiver /app disable   # awaryjne wyłączenie (usuwa konsumenta kolejki), potem: docker compose stop archiver
```

Zatrzymany archiwizator **nie gubi danych**: paczki czekają w kolejce, a po jej zapełnieniu ingest odmawia przyjęcia (503) i dane czekają u agentów. Archiwum wyłącza się polityką w panelu; `disable` zostaje na sytuację awaryjną, gdy archiwizator ma w ogóle nie działać.

W laboratorium archiwum leży na dysku lokalnym. Ochrona polega tu na wykrywaniu zmian przez łańcuch hashy, a nie na blokadzie zapisu. Backend S3 z Object Lock w trybie compliance dojdzie później. Napastnik z pełnym dostępem do dysku **i** bazy może przepisać cały łańcuch, dlatego docelowo hash ostatniego manifestu będzie też zapisywany poza systemem.

### Role bazy Saga

Każda usługa łączy się z PostgreSQL własną rolą, bez uprawnień superużytkownika. Role zakłada skrypt `saga/init/10-roles.sh`:

| Rola | Kto | Uprawnienia |
|---|---|---|
| `saga_admin` | administrator (ręcznie) | superużytkownik, właściciel bazy; żadna usługa go nie używa |
| `siem_api` | panel | właściciel tabel panelu (schemat `public`); archiwum tylko czyta i może zlecić weryfikację |
| `siem_archiver` | archiwizator | właściciel spisu archiwum (schemat `urd`); bez dostępu do kont i agentów |

Przejęcie panelu nie daje więc możliwości zmiany ani usunięcia spisu archiwum, ani usunięcia bazy. Nowa instalacja zakłada role sama przy pierwszym starcie. Instalację sprzed rozdzielenia ról przenosi się raz:

```bash
docker compose stop api archiver
docker compose up -d saga
docker compose exec -T saga sh /docker-entrypoint-initdb.d/10-roles.sh
docker compose up -d api archiver
```

Wcześniej trzeba dopisać do `.env` hasła `SAGA_ADMIN_PASSWORD` i `SAGA_ARCHIVER_PASSWORD`, np. `openssl rand -hex 24`. Superużytkownik, z którym baza była zakładana, zostaje przemianowany na `saga_admin`, bo PostgreSQL nie pozwala odebrać mu uprawnień. Konsola administratora: `docker compose exec saga psql -U saga_admin -d saga`.

### Eksport dla audytora (Urd)

Administrator zleca eksport w panelu: zakładka *Urd → Eksport dla audytora*, zakres pełnych godzin archiwizacji (do 31 dni) i obowiązkowy powód. Archiwizator przygotowuje paczkę `urd-eksport-<nr>-<od>-<do>.tar` w `/srv/heimdall/export` (`SIEM_ARCHIVE_EXPORT_PATH`). Paczkę da się w całości odczytać i sprawdzić **bez Heimdalla**, np. przy zgłoszeniu incydentu do CSIRT albo organu nadzoru. Zawiera:

- **Zdarzenia do odczytu** (`zdarzenia/`):
  - `RRRR-MM-DD_GG.ndjson.gz`: jedno zdarzenie w linii, pola według Elastic Common Schema (`@timestamp`, `host.name`, `event.code`, `user.name`, `source.ip`…). Pełny oryginalny XML Windows jest w `event.original`. Plik da się wczytać do Elastic, Splunk czy Sentinel albo przeglądać przez `zcat` i `jq`.
  - `zdarzenia.csv`: najważniejsze kolumny dla Excela (UTF-8, separator średnik, do miliona wierszy).
- **Dowód** (`segments/`, `chain/`): oryginalne segmenty, bajt w bajt to, co przyszło od agentów, oraz manifesty od pierwszej godziny zakresu do najnowszego (łańcuch z kotwicą).
- **Czytnik** `odczytaj.exe` w katalogu głównym paczki, dla odbiorcy na Windows bez wiedzy technicznej. Wystarczy dwuklik w rozpakowanym folderze albo przeciągnięcie na niego pliku `.tar`. Program sprawdza integralność tak samo jak skrypt i zapisuje w podfolderze `ODCZYT/`:
  - `RAPORT.txt`: wynik sprawdzenia z kotwicą, kto, kiedy i po co zlecił eksport, zdarzenia wymagające uwagi (czyszczenie dziennika, konta i grupy, nowe usługi i zadania z nazwą i ścieżką, nieudane logowania według konta i adresu), statystyki;
  - `zdarzenia/RRRR-MM-DD.txt`: wszystkie zdarzenia dnia w kolejności czasu (czas polski i UTC), z polskim opisem kodu (np. „4625 – Nieudane logowanie”) i danymi zdarzenia jako `Nazwa = wartość` z objaśnieniami (np. `LogonType = 10 (zdalny pulpit (RDP))`). Pliki mają po 50 tys. zdarzeń, czyli ok. 50 MB.

  Po zakończeniu raport otwiera się w Notatniku. `ODCZYT/` nie jest częścią paczki i nie wpływa na wynik sprawdzenia. Program nie jest podpisany cyfrowo, więc Windows może pokazać ostrzeżenie SmartScreen („Więcej informacji → Uruchom mimo to”). Odbiorca, który nie uruchamia cudzych programów, ma skrypt w Pythonie i ręczne sprawdzenie sum. Program buduje i dołącza `deploy/lab/deploy.sh tools`, który zapisuje go w `~/siem-lab/export-tools`.
- **Sprawdzenie** (`narzedzia/odczytaj_segmenty.py`): skrypt na samą bibliotekę standardową Pythona 3. Sprawdza:
  - sumy plików;
  - łańcuch;
  - segmenty i każdą paczkę;
  - że część czytelna zawiera dokładnie te same zdarzenia, czyli identyfikatory i oryginalny XML, co oryginały.

  Z opcją `--wypisz` czyta zdarzenia wprost z oryginałów.
- `export.json` (kto, kiedy, po co i jaki zakres), `README.txt` dla odbiorcy i `SHA256SUMS`.

Przy zapisie każdy segment jest porównywany z manifestem, więc niezgodne archiwum przerywa eksport. Panel pokazuje SHA-256 całej paczki, który warto wpisać do protokołu przekazania. Zlecenie i każde pobranie trafiają do audytu, a paczki są usuwane po 7 dniach (`SIEM_ARCHIVE_EXPORT_KEEP_DAYS`).

Uprawnienia: rola panelu może tylko złożyć zlecenie (wybrane kolumny) i czytać jego stan. Nie oznaczy go jako gotowego i nie wskaże dowolnego pliku do pobrania.

Sprawdzenie paczki bez dostępu do systemu:

```bash
siem-archiver check-export urd-eksport-1-2026100710-2026100716.tar
```

Polecenie Heimdalla sprawdza to samo co skrypt, czyli:

- sumy plików;
- ciągłość łańcucha;
- zgodność segmentów z manifestami;
- sumę każdej paczki agenta;
- zgodność części czytelnej z oryginałami.

Kod wyjścia 1 oznacza niezgodności. Na końcu polecenie wypisuje kotwicę, czyli SHA-256 najnowszego manifestu, do porównania z wartością zapisaną niezależnie. Bez programu audytor może sprawdzić paczkę ręcznie według `README.txt`, zaczynając od `sha256sum -c SHA256SUMS`.

Zakres dotyczy czasu przyjęcia paczek przez serwer, nie czasu zdarzeń. Eksport można ograniczyć do wybranych grup agentów i agentów (grupy są rozwijane do agentów w chwili zlecenia). Filtr dotyczy części czytelnej: zdarzeń, CSV i raportu `odczytaj.exe`. Dowód (`segments/`) zawsze zawiera wszystkie paczki z wybranych godzin, bo tylko cały segment można sprawdzić względem manifestu. Sprawdzenie porównuje część czytelną z oryginałami wybranych agentów, więc usunięcie filtra z `export.json` też wychodzi jako niezgodność.

### Odtworzenie z archiwum (replay)

Administrator zleca odtworzenie w panelu, w zakładce *Urd → Odtworzenie*: zakres godzin archiwizacji (do 31 dni), opcjonalnie lista agentów i obowiązkowy powód. Służy np. do analizy danych starszych niż retencja bazy zdarzeń albo do ponownej normalizacji po zmianie parsera.

```
archiwum ──► siem-archiver ──► NATS SIEM_REPLAY_RAW ──► normalizer-replay ──► SIEM_REPLAY_EVENTS ──► writer-replay ──► siem.events_replay
```

- **Osobna ścieżka.** Te same programy (`SIEM_PIPELINE=replay`) pracują na osobnych strumieniach. Odtwarzanie nie zajmuje kolejki agentów i nie powoduje odmów 503. Normalizator replay ma 2 wątki, żeby nie zabierać CPU bieżącym zdarzeniom.
- **Osobna tabela** `siem.events_replay`, z numerem zlecenia (`replay_id`) i czasem odtworzenia (`replayed_at`). Dane żyją 7 dni od odtworzenia (`SIEM_REPLAY_TTL_DAYS`). Odtworzenie nie zmienia danych produkcyjnych: ClickHouse usuwa duplikaty tylko w obrębie partycji, więc wspólna tabela mogłaby podmienić bieżące wiersze. Odtworzone zdarzenia nie trafią też do detekcji. `ingested` zostaje oryginalnym czasem przyjęcia paczki.
- **W Mímirze** przełącznik „Odtworzone z archiwum” przeszukuje tę tabelę. Link „pokaż w Mímirze” przy zleceniu ustawia zakres.
- **Kontrola danych.** Każda paczka i każdy segment są przy odczycie porównywane z sumami, więc niezgodne archiwum przerywa odtwarzanie. Gdy strumień odtwarzania jest pełny, archiwizator czeka.

Istniejąca baza ClickHouse potrzebuje jednorazowo nowej tabeli. Nowe instalacje zakładają ją same:

```bash
docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/02-replay.sh
```

Sprawdzone na VM: odtworzenie 2446 paczek trwało 1,5 s i dało 100 117 zdarzeń. Wszystkie są identyczne z zapisanymi wcześniej w `siem.events` i mają oryginalne czasy przyjęcia.

### Kopie zapasowe

Skrypt `backup.sh` (cron użytkownika `siem`, codziennie o 02:15) tworzy **jedną zaszyfrowaną paczkę** `heimdall-RRRRMMDD-GGMM-k<id>.tar.gpg` z:

- zrzutem bazy Saga (`pg_dump`): konta, agenci, certyfikaty, grupy, spis i polityka archiwum, kanały powiadomień. Zrzut jest sprawdzany przez `pg_restore --list` przed zaszyfrowaniem;
- `certs/` (w tym klucz CA agentów) i `.env`.

Szyfruje `gpg` (AES-256). Paczkę da się odszyfrować na dowolnym Linuksie albo na Windows z Gpg4win, bez Heimdalla. `k<id>` w nazwie to identyfikator hasła, którym ją zaszyfrowano.

**Hasło kopii** (uruchamia administrator na VM, w `~/siem-lab`):

```bash
./backup.sh haslo init    # pierwsze hasło – pokazywane raz; zapisz je poza serwerem
./backup.sh haslo pokaz   # pokaż obecne hasło
./backup.sh haslo zmien   # nowe hasło dla kolejnych kopii (stare kopie otwiera tylko stare hasło)
```

Hasło leży w `~/.heimdall-backup.pass` (tylko dla właściciela), poza katalogiem stosu i poza samą kopią. **Bez hasła kopii nie da się odtworzyć** – po utracie VM potrzebne jest hasło zapisane przez administratora. Bez hasła `backup.sh` nie robi kopii, a alert „brak udanej kopii” zgłasza to po 26 h.

**Poza VM** (`SIEM_BACKUP_REMOTE` w `.env`, np. `heimdall@192.168.88.180:/mnt/HDD/TANK/heimdall_backup`): po każdej kopii skrypt wysyła przez SSH z kluczem `~/.ssh/heimdall_backup`:

- `config/` – zaszyfrowane paczki kopii;
- `urd/` – przyrosty archiwum NIS2: nowe segmenty i manifesty od poprzedniej wysyłki w paczce zaszyfrowanej tym samym hasłem. Segmenty się nie zmieniają, więc codzienna wysyłka to tylko dane z ostatniej doby.

Na serwerze kopii paczki są trzymane 90 dni (`SIEM_BACKUP_REMOTE_KEEP_DAYS`), lokalnie 14 dni (`SIEM_BACKUP_KEEP_DAYS`, katalog `/srv/heimdall/backup`). Użytkownik na serwerze kopii potrzebuje tylko SSH z kluczem publicznym z `~/.ssh/heimdall_backup.pub` i prawa zapisu do katalogu kopii. Alert „kopia nie trafiła poza VM od ponad 26 h” pilnuje wysyłki.

```bash
crontab -e   # wpis: 15 2 * * * /home/siem/siem-lab/backup.sh >> /home/siem/siem-lab/backup.log 2>&1
./backup.sh  # kopia na żądanie
```

**Odtworzenie całego systemu na czystej VM** (Docker zainstalowany, stos skopiowany `deploy.sh config` i usługi zbudowane):

```bash
scp heimdall@192.168.88.180:/mnt/HDD/TANK/heimdall_backup/config/heimdall-….tar.gpg .
rsync -a heimdall@192.168.88.180:/mnt/HDD/TANK/heimdall_backup/urd/ urd/   # opcjonalnie: archiwum NIS2
./restore.sh heimdall-….tar.gpg urd/
```

`restore.sh` pyta o hasło kopii, przywraca `certs/` i `.env`, bazę Saga i (z drugim argumentem) archiwum NIS2, a potem uruchamia stos. Kopia nie zawiera zdarzeń z ClickHouse (kilka dni) – można je odtworzyć z archiwum w panelu (Urd → Odtworzenie).

### Alerty (Grafana)

Do czasu modułu alertów (Gjallarhorn, etap 4) awarie zgłasza Grafana. Reguły są w `grafana/provisioning/alerting/heimdall.yaml`, folder SIEM, grupa „Heimdall – zdrowie”:

- weryfikacja archiwum wykryła niezgodności;
- archiwizator nie działa;
- archiwizacja wyłączona w polityce;
- zaplanowane osłabienie polityki archiwum (karencja – czas na anulowanie);
- archiwizacja wstrzymana z braku miejsca;
- mało miejsca na dysku archiwum albo na dysku systemowym (< 15%);
- weryfikacja nieaktualna;
- brak kopii zapasowej od ponad 26 h;
- kolejka zapełniona ponad 80%;
- ingest odmawia przyjęcia zdarzeń (503).

Stan alertów widać w Grafanie (*Alerting → Alert rules*). Grafana wysyła je do siem-api (punkt kontaktowy w `provisioning/alerting/contact.yaml`, wewnętrzny port 8081 dostępny tylko w sieci stosu, token `SIEM_ALERT_RELAY_TOKEN` w `.env`). siem-api przekazuje je na kanały ustawione w panelu.

### Powiadomienia (panel → Powiadomienia)

Administrator dodaje kanały: **Discord** (adres webhooka kanału) albo **webhook** (POST z JSON `{event, severity, title, text, fields, at}`, np. do n8n lub własnej usługi). Dla każdego kanału wybiera, co ma dostawać:

- **alerty zdrowia systemu** z Grafany (z wiadomością „Rozwiązane” po ustąpieniu problemu);
- **kotwicę archiwum Urd**, codziennie o `SIEM_ANCHOR_HOUR` (domyślnie 7:00): numer i SHA-256 najnowszego manifestu łańcucha. Kopia u odbiorcy jest dowodem niezależnym od systemu – kto przepisze archiwum razem ze spisem w bazie, nie zmieni wiadomości wysłanych wcześniej. Panel porównuje wysłane kotwice z łańcuchem („zgodna z łańcuchem”), a przycisk „Wyślij kotwicę teraz” wysyła ją poza terminem.

Adres webhooka jest sekretem: przechowuje go tylko baza panelu, API go nie zwraca (panel pokazuje początek i 4 ostatnie znaki), a błędy wysyłki nie zawierają adresu. Wyłączenie kanału, rezygnacja z rodzaju powiadomień, zmiana adresu i usunięcie wymagają ponownego podania hasła i trafiają do audytu. Dziennik wysyłek jest trzymany 90 dni, a wpisy kotwic bezterminowo. Później te same kanały dostaną alerty detekcji (Gjallarhorn).

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
| `SIEM_NORMALIZER_WORKERS` | liczba rdzeni | paczki przetwarzane równolegle przez jedną kopię normalizatora |

Zaległości widać w logach normalizatora i writera: od 50% zajętości ostrzeżenie „kolejka rośnie”. To sygnał, że trzeba dołożyć kopie.

### Metryki i test obciążenia

Usługi serwera wystawiają metryki Prometheus na porcie 9100 (tylko w sieci Dockera). Prometheus zbiera je co 5 s i sam znajduje dodatkowe kopie usług. W Grafanie jest pulpit **„SIEM – zdrowie potoku”**:

- przepływ zdarzeń przez etapy;
- odmowy 429 i 503;
- zajętość i zaległości kolejek;
- opóźnienie od przyjęcia do zapisu;
- CPU i pamięć usług;
- metryki ClickHouse.

Interfejs Prometheusa jest dostępny tylko z VM (`127.0.0.1:9090`, np. przez `ssh -L 9090:127.0.0.1:9090`).

Generator ruchu udaje wielu agentów. Każdy dostaje własny certyfikat, wystawiany w pamięci z `certs\ca.key`, i realistyczną mieszankę zdarzeń Security, System i Application:

```powershell
go build -o bin/siem-loadgen.exe ./server/cmd/siem-loadgen
bin\siem-loadgen.exe -url https://192.168.88.98:8443/v1/ingest -agents 500 -eps 20 -duration 3m
```

Co 10 s generator pokazuje zdarzenia wygenerowane i przyjęte, odmowy, opóźnienie odpowiedzi i bufor agentów. Gdy bufor agenta się przepełni (`-backlog`, domyślnie 50 000), zdarzenia przepadają jak w nadpisanym dzienniku Windows i generator je liczy. Zdarzenia testowe mają `agent_id` z prefiksem `agt-load-` i znikają z bazy razem z retencją (5 dni).

Zasady skalowania, obsługa przeciążenia, pomiary i znane ograniczenia: [docs/ROADMAP.md – załącznik E](docs/ROADMAP.md#załącznik-e-skalowanie-i-przeciążenie).
