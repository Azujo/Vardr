# SIEM – własny system SIEM

Vardr – własny SIEM według roadmapy [docs/ROADMAP.md](docs/ROADMAP.md) (nazewnictwo: załącznik D).

Obecny stan: **MVP gotowe (etapy 0–8, październik 2026)**. Działają agent Windows z ochroną przed wyłączeniem, kolektor syslog (FortiGate, MikroTik), konektor Entra ID, potok NATS → ClickHouse, detekcja Sigma w dwóch silnikach z korelacjami między źródłami, archiwum NIS2 z łańcuchem hashy i panel Hliðskjálf. Potok sprawdzono przy 7000 zdarzeń/s przez 8 h. Przebieg prac i znane luki: [docs/PODSUMOWANIE.md](docs/PODSUMOWANIE.md).

## Dokumentacja

Pełna dokumentacja jest w [docs/](docs/README.md):

- [Architektura](docs/architektura.md) – składniki, przepływ zdarzenia, kolejki, bazy, detekcja, struktura repozytorium;
- [Programy](docs/programy.md) – każdy program: polecenia, flagi, zmienne środowiskowe, porty, metryki;
- [Panel](docs/panel.md) – moduły, role, język wyszukiwania, praca z alertem;
- [Reguły detekcji](docs/reguly.md) – jak pisać, testować i wdrażać reguły; reguły wbudowane;
- [Dekodery](docs/dekodery.md) – dekodery syslog i API, nowe urządzenie krok po kroku;
- [Operacje](docs/operacje.md) – wdrażanie, kopie, retencja, migracje, diagnostyka;
- [Testy obciążeniowe](docs/testy-obciazeniowe.md) – generator ruchu, monitor, sprzątanie, wyniki;
- [Rozwój](docs/rozwoj.md) – budowanie, testy, CI, konwencje, jak dodać źródło, regułę albo migrację.

Ten plik zawiera instrukcje instalacji i szczegóły poszczególnych funkcji.

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
bin\vardr-agent.exe -config agent\configs\agent.lab.yaml check
bin\vardr-agent.exe -config agent\configs\agent.lab.yaml run
```

Zdarzenia trafiają do `data\events.ndjson`, stan agenta do `data\agent\state.json`.

## Instalacja agenta na komputerze

1. Na stacji administratora przygotuj paczkę dla komputera (certyfikat z
   identyfikatorem agenta, CA, program i domyślny adres serwera):

   ```powershell
   go build -o bin\vardr-agent.exe .\agent\cmd\vardr-agent
   bin\siem-pki.exe package -id agt-pc01 -server 192.168.88.98
   ```

   Powstaje folder `dist\agt-pc01` (ignorowany przez git – zawiera klucz prywatny).

2. Skopiuj folder na komputer i w PowerShell lub cmd **jako administrator**:

   ```powershell
   .\vardr-agent.exe install                       # adres z server.txt albo pytanie o adres
   .\vardr-agent.exe install -server 10.0.0.5      # adres podany wprost
   .\vardr-agent.exe install -profile dc           # profil zdarzeń: workstation | server | dc
   ```

   Instalator kopiuje program do `C:\Program Files\SiemAgent`, konfigurację
   i certyfikaty do `C:\ProgramData\SiemAgent` (dostęp tylko SYSTEM
   i Administratorzy), sprawdza połączenie z serwerem, rejestruje usługę
   `SiemAgent` (start automatyczny, restart po awarii), uruchamia ją i dodaje
   `C:\Program Files\SiemAgent` do PATH.

3. Sterowanie (nowe okno, z dowolnego folderu):

   | Polecenie | Działanie | Administrator |
   |---|---|---|
   | `vardr-agent status` | stan usługi; szczegóły: serwer, kanały, liczniki, limity | szczegóły – tak |
   | `vardr-agent start` / `restart` | uruchomienie; restart agenta w procesie usługi | tak |
   | `vardr-agent stop [-token T]` | zatrzymanie (agent chroniony: token z panelu) | tak |
   | `vardr-agent test` | test połączenia z serwerem (TLS + certyfikaty) | tak |
   | `vardr-agent set-server <adres>` | zmiana adresu, test, restart agenta | tak |
   | `vardr-agent upgrade [-token T]` | aktualizacja programu (z folderu nowej wersji) | tak |
   | `vardr-agent uninstall [-token T] [-purge]` | odinstalowanie: usługa, program i klucz prywatny (`-purge`: także konfiguracja, bufor i certyfikaty) | tak |

Usługa działa jako LocalSystem (dostęp do kanału Security). Log: `C:\ProgramData\SiemAgent\agent.log`.

### Instalator MSI (od wersji 0.6)

`deploy.sh agent` buduje na serwerze `vardr-agent.msi` (narzędziem `wixl` w kontenerze, z CA tej instalacji).

**Jeden plik do podwójnego kliknięcia (od 0.7.3).** Panel przy tokenie (Bifröst → „Pobierz instalator (MSI)”) wydaje `vardr-agent-<nazwa>.msi` z wpisanym adresem serwera i tokenem: instalator ma właściwości `SERVER` i `TOKEN` z wypełniaczami stałej długości, a panel podmienia je w pliku przy pobraniu (`internal/msipatch` – struktura MSI się nie zmienia, plik czyta `msiinfo`). Podwójne kliknięcie instaluje i rejestruje agenta, na komputerze z agentem – aktualizuje go (token jest wtedy pomijany). Ten sam plik wdraża się przez GPO, Intune albo SCCM bez parametrów. Plik zawiera token, więc działa jak token: krótka ważność albo limit instalacji. Do samej aktualizacji Huginn ma „Pobierz aktualizację agenta (MSI)” – bazowy instalator bez tokenu (nowego komputera nim nie zarejestrujesz – instalator zgłosi brak tokenu). Paczka ZIP zostaje jako opcja.

Wdrożenie z parametrami (Intune, SCCM, skrypt GPO), jako SYSTEM lub administrator – parametry mają pierwszeństwo przed wartościami wpisanymi w plik:

```powershell
msiexec /i vardr-agent.msi /qn SERVER=192.168.88.98 TOKEN=hdt_…   # instalacja i rejestracja tokenem
msiexec /i vardr-agent.msi /qn                                    # aktualizacja do nowszej wersji (rejestracja zostaje)
msiexec /x vardr-agent.msi /qn UNINSTALL_TOKEN=XXXXX-XXXXX-XXXXX-XXXXX   # odinstalowanie chronionego agenta
```

MSI kopiuje program i CA do `C:\Program Files\SiemAgent`, a potem uruchamia `vardr-agent msi-install` (rejestracja tokenem i usługa – ta sama ścieżka co `install`). Nowsza wersja najpierw usuwa starą (bez danych), więc aktualizacja nie zużywa tokenu. Agent zainstalowany wcześniej bez MSI zostaje przejęty: MSI zatrzymuje go, podmienia program i zostawia rejestrację. Token nie trafia do dziennika instalatora. Przebieg kroków agenta: `C:\ProgramData\SiemAgent\msi.log`.

Każde wydanie agenta potrzebuje nowego numeru wersji (`const version` w `agent/cmd/vardr-agent/main.go`). Przebudowany instalator tej samej wersji `wixl` instaluje obok poprzedniego jako drugi produkt (nie obsługuje `AllowSameVersionUpgrades`).

### Ochrona przed zatrzymaniem i deinstalacją (od wersji 0.7)

Pełnej blokady nie ma: lokalny administrator zawsze może zmienić uprawnienia usługi, a konto SYSTEM może wszystko. Cel to **utrudnić i wykryć**. Ochronę włącza grupa agentów (panel → Grupy agentów → „Ochrona agenta”, domyślnie włączona). Agent bez konfiguracji z panelu jest bez ochrony.

- **Uprawnienia usługi.** Administrator sprawdzi stan usługi, uruchomi ją i zrestartuje agenta (`vardr-agent restart` – polecenie 128 do usługi). Nie może jej zatrzymać, wstrzymać, przekonfigurować ani usunąć: `sc stop` i `services.msc` dostają odmowę dostępu. Zostaje mu prawo zmiany uprawnień – to granica ochrony.
- **Token deinstalacji.** Panel → Huginn → agent → „Token deinstalacji”: rola administratora, powód i ponowne podanie hasła, wpis w audycie. Token jest jednorazowy, działa tylko na tym komputerze, domyślnie przez 24 h (do 7 dni). Panel pokazuje go raz; w bazie i na komputerze jest tylko skrót. Nowy token unieważnia poprzedni. Polecenie z tokenem samo pobiera świeżą konfigurację z panelu, więc token działa od razu. Użyty token panel oznacza na podstawie raportu agenta.
- **Wycofanie po deinstalacji (od 0.7.4).** Deinstalacja usuwa klucz prywatny agenta (`certsgent.key`); konfiguracja i bufor zostają (`-purge` usuwa wszystko). Gdy agent zgłosi deinstalację tokenem wydanym w panelu dla tego komputera, panel unieważnia jego certyfikaty (rozsyłane do ingestu jak przy ręcznym unieważnieniu) i zapisuje `agent_retired` w audycie. Agent ma w Huginnie stan „wycofany” – znika z domyślnej listy (filtr „Wycofani”), historia zostaje. Ponowna instalacja na tym komputerze to nowa rejestracja tokenem i nowy identyfikator (identyfikatory nigdy nie są używane ponownie – zdarzenia z jednego identyfikatora zawsze pochodzą z jednego klucza).
- **Pilnowanie co 30 s.** Agent sprawdza uprawnienia usługi, typ uruchamiania i ścieżkę programu, zarówno w menedżerze usług, jak i w rejestrze. Zmianę zgłasza i cofa.
- **Zdarzenia ochrony.** Dziennik `tamper.jsonl` w katalogu stanu; agent wysyła w heartbeacie zdarzenia z ostatnich 7 dni. Zdarzenie z chwili zatrzymania dociera więc także po ponownym starcie. Przy zatrzymaniu agent wysyła od razu ostatni heartbeat z powodem.

| Zdarzenie | Alert „Próba sabotażu agenta” |
|---|---|
| zatrzymanie usługi bez tokenu (np. po `sc sdset` albo z konta SYSTEM) | wysoki |
| zmiana uprawnień albo konfiguracji usługi (agent ją cofnął) | wysoki |
| zatrzymanie „tokenem”, którego panel nie wydał (podrobiony `managed.json`) | wysoki |
| aktualizacja przez instalator, po której agent nie wrócił w ciągu 15 min | wysoki |
| zabicie procesu (`taskkill /f`; usługa wstaje sama po 5 s) | średni |
| `vardr-agent stop` / `uninstall` / `msiexec /x` bez tokenu albo ze złym tokenem | średni |
| zatrzymanie, aktualizacja i deinstalacja tokenem; zamknięcie systemu | brak (wpis w panelu) |

`vardr-agent status` i strona agenta w panelu pokazują stan ochrony i ostatnie zdarzenia. Agent zatrzymany bez tokenu ma na liście czerwony znacznik „zatrzymany bez tokenu”. Reguła Sigma `system_security_service_stopped` dotyczy teraz tylko Sysmona: zatrzymania agenta zgłasza reguła wbudowana, która odróżnia zatrzymanie tokenem.

Awaryjnie, gdy komputer nie ma łączności z panelem i nie da się użyć tokenu: `sc sdset SiemAgent` przywraca zwykłe uprawnienia, a potem `sc stop` / `sc delete`. Panel dostanie wtedy alert – to zamierzone.

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
vardr-agent status
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
i Administratorzy. `vardr-agent check` pokazuje, czy klucz i katalog stanu są
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

**Gotowy skrypt:** [deploy/windows/vardr-gpo.ps1](deploy/windows/vardr-gpo.ps1) – uruchomiony na kontrolerze domeny (administrator domeny) tworzy i podłącza GPO „Vardr - polityka audytu” (cała domena: zaawansowana polityka inspekcji, linia poleceń w 4688, logowanie bloków PowerShell, dziennik Security 256 MB) oraz „Vardr - dzienniki DC” (Security 1 GB na kontrolerach domeny). Można go uruchamiać wielokrotnie. Sprawdzony w laboratorium (Windows Server 2025, Windows 11): nieudane logowania (4625, 4776, 4768), zmiany kont i grup (4720, 4732, 4733, 4726), procesy z linią poleceń (4688) i PowerShell (4104) docierają do Mímira.

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
- Stan bufora widać w `vardr-agent status` i w panelu (Huginn → agent). Panel zgłasza problem, gdy paczki czekają dłużej niż 5 minut, gdy bufor jest pełny i gdy coś utracono.

**Zegar:** agent przy każdym heartbeacie mierzy odchylenie swojego zegara od serwera (nagłówek `X-Vardr-Time`) i co 5 minut sprawdza usługę czasu Windows (W32Time). Panel zgłasza odchylenie ponad 60 s i wyłączoną usługę czasu (zatrzymana jest normalna poza domeną – Windows uruchamia ją na żądanie).

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

Wszystkie te komunikaty trafiają do logu agenta, do `vardr-agent status` i (gdy agent działa jako usługa) do Podglądu zdarzeń (Application, źródło `SiemAgent`).

## Testy

```powershell
go vet ./...
go test ./...
```

Na GitHubie testy uruchamiają się automatycznie przy każdym pushu ([.github/workflows/ci.yml](.github/workflows/ci.yml)):

- **Linux:** `gofmt`, `go vet`, testy z wykrywaniem wyścigów (`-race`), 60 s fuzzingu parsera XML i budowanie usług serwera;
- **Windows:** `go vet`, testy agenta i budowanie `vardr-agent.exe`.

Wynik widać w zakładce *Actions* repozytorium.

## Czego jeszcze nie ma (kolejne etapy)

- sprawdzanie polityki audytu (razem z heartbeatem)
- odczyt plików dziennika przez agenta (np. IIS W3C – dekoder `csv` już je rozbiera) i syslog po TLS w kolektorze
- logi M365 (Management Activity API) i prawdziwy tenant Entra ID (konektor gotowy, w laboratorium symulator)
- lokalna baza GeoIP (kraj dla VPN i innych źródeł)

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
deploy/lab/deploy.sh archiver agent     # wybrane cele (agent = vardr-agent.exe do paczek)
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

**Huginn – agenci:** agent (od wersji 0.4.0) co minutę wysyła heartbeat ze swoim stanem, czyli tym samym, co pokazuje `vardr-agent status`. Trasa: `POST /v1/heartbeat` na siem-ingest (mTLS) → strumień NATS `SIEM_HEARTBEATS` (ostatni heartbeat na agenta) → siem-api → tabela `agents` w Sadze.

Panel pokazuje dla każdego agenta:

- stan online lub offline (offline po 3 minutach bez heartbeatu);
- wersję, system, adres IP i ważność certyfikatu;
- kanały, liczniki zdarzeń, zużycie zasobów i ostrzeżenia;
- czytelną listę problemów, np. „kanał Security: brak dostępu”, „certyfikat wygasa za 5 dni”, „wysyłka zdarzeń nieudana”.

Agenci ze starszych wersji wysyłają zdarzenia, ale nie pojawiają się na liście, dopóki nie zostaną zaktualizowani. Generator ruchu też wysyła heartbeaty (`-heartbeat`, domyślnie włączone), więc listę da się sprawdzić na tysiącach agentów.

**Bifröst – wdrażanie agentów tokenem:** administrator tworzy w panelu token rejestracyjny: nazwa, profil zdarzeń, ważność i limit instalacji. Token jest widoczny raz, a w bazie zostaje tylko jego skrót. Do tokenu panel daje instalator MSI z wpisanym adresem serwera i tokenem (jeden plik – instalacja albo aktualizacja podwójnym kliknięciem), paczkę ZIP (program agenta, główne CA, adres serwera, token, `install.cmd`) – oba **bez klucza prywatnego** – i gotowe polecenie do GPO lub Intune:

```bash
vardr-agent.exe install -server 192.168.88.98 -token hdt_…
```

Przebieg instalacji:

1. Agent generuje klucz na komputerze. Klucz nigdy go nie opuszcza.
2. Agent wysyła prośbę o certyfikat (CSR) z tokenem do panelu (`POST /enroll/v1/register`, port 8444).
3. Panel nadaje identyfikator z nazwy hosta. Zajęty identyfikator dostaje dopisek, więc nikt nie przejmie cudzej tożsamości.
4. Panel wydaje certyfikat na 90 dni, a agent odnawia go sam na 30 dni przed końcem (`/enroll/v1/renew`, z nowym kluczem).

Certyfikaty podpisuje osobne **CA agentów** (`siem-pki agents-ca`), które może wystawiać wyłącznie certyfikaty klientów. Główne CA zostaje offline, a agenci sprawdzają nim serwer.

**Unieważnianie:** w panelu (Huginn → agent → „Unieważnij certyfikat”). Panel zapisuje unieważnienie w NATS (`SIEM_REVOKED_CERTS`), a ingest odrzuca taki certyfikat przy nawiązywaniu połączenia.

Inne polecenia agenta:

- `vardr-agent enroll -server … -token … -dir …`: rejestracja bez instalowania usługi, np. do testów;
- `vardr-agent upgrade`: aktualizacja programu z folderu nowej wersji, z zachowaniem konfiguracji, certyfikatów i stanu.

Przygotowanie serwera:

- `binsiem-pki.exe agents-ca`, potem `agents-ca.crt` i `agents-ca.key` do `~/siem-lab/certs`;
- `vardr-agent.exe` do `~/siem-lab/agent-dist`;
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

Panel pokazuje przy agencie, czy jego konfiguracja jest aktualna (wersja z heartbeatu porównana z wersją grupy). `vardr-agent status` pokazuje źródło konfiguracji. Zmienna `SIEM_CONFIG_POLL_SECONDS` przyspiesza pobieranie (diagnostyka).

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
- **Alerty** zapisuje w Sadze (schemat `gjallarhorn`, rola `siem_detector`). Para (reguła, zdarzenie) trafia do alertu najwyżej raz, więc ponowne dostarczenie i restart nie dublują alertów. Reguła z `vardr.group_by` łączy trafienia z tymi samymi wartościami pól w oknie `vardr.suppress` (domyślnie 1 h) w jeden alert z licznikiem.
- **Powiadomienia:** alert i wpis w outboxie powstają w jednej transakcji; panel wysyła je na kanały z zaznaczonym „alerty detekcji” (Powiadomienia), z ponawianiem (najwyżej 30 prób, ok. doby). Każdy kanał ma **filtr alertów**: od jakiego poziomu i z których reguł (wszystkie / tylko wybrane / wszystkie poza wybranymi) – np. Discord tylko „wysoki” i „krytyczny”, a webhook do systemu zgłoszeń wszystko. Zawężenie filtru wymaga ponownego podania hasła (jak wyłączenie kanału). Wartości ze zdarzeń są w Discordzie escapowane (atakujący nie podsunie linku w treści polecenia).
- **Retencja alertów:** detektor co 6 h usuwa alerty zamknięte dawniej niż `SIEM_ALERT_RETENTION_DAYS` (domyślnie 365 dni, 0 = bez usuwania) razem z ich zdarzeniami i osią czasu oraz wysłane powiadomienia starsze niż 30 dni. Otwarte i analizowane alerty zostają zawsze.
- **Burza alertów:** najwyżej 5 osobnych powiadomień o nowych alertach jednej reguły w 10 min (`SIEM_ALERT_NOTIFY_PER_RULE`, `SIEM_ALERT_NOTIFY_WINDOW` w siem-api; 0 = bez limitu). Kolejne nie przepadają: po oknie przychodzi jedna wiadomość „[ZBIORCZO] reguła – N alertów” z przykładowymi komputerami i linkiem do listy w panelu. Alerty krytyczne i wiadomości o rozwiązaniu idą zawsze osobno.
- **Utrata i powrót agenta:** w grupie agentów „Alarm po utracie łączności” (próg) i „Powiadamiaj także o powrocie” – wtedy po powrocie agenta przychodzi wiadomość „[ROZWIĄZANY]” z długością przerwy (przez te same kanały i filtry).
- **Samokontrola detektora:** gdy pętla detekcji nie robi postępu przez 3 min (silnik zapytań – 15 min), proces kończy się sam, Docker uruchamia go ponownie, a stan progów wraca z Sagi.
- **Himinbjörg – stan systemu (etap 5d):** strona w panelu (i karta na stronie startowej) z 23 kontrolami z Prometheusa (`SIEM_PROMETHEUS_URL` w siem-api): usługi, potok (przyjmowanie, odmowy, zapełnienie kolejek, błędy zapisu, kwarantanna), detekcja (reguły, błędy, zaległość silnika zapytań), archiwum NIS2 (weryfikacja, archiwizacja, miejsce), kopie zapasowe (lokalna i na NAS), serwer (dysk, CPU, pamięć). Progi jak w alertach Grafany; przy problemie – podpowiedź, co sprawdzić.
- **Reguły w panelu (etap 5c):** każda zmiana treści pliku to nowa wersja (historia z różnicami między wersjami); administrator może regułę wyłączyć albo włączyć ponad ustawienie w pliku – wyłączenie wymaga powodu i ponownego podania hasła, trafia do audytu, a detektor stosuje je w ciągu 30 s (przycisk „wróć do ustawienia z pliku”); „Przetestuj” wykonuje regułę (także nową, wklejoną) na zdarzeniach z ostatnich 1–168 godzin w ClickHouse i pokazuje dopasowania oraz alerty, które by powstały – liczone tym samym kodem co w detektorze. Treść reguł nadal tylko w repozytorium.
- **Panel:** *Gjallarhorn* i *Reguły detekcji* (treść, otwarte alerty, błędy wczytania). Praca z alertami (etap 5a):
  - lista z filtrami (stan, poziom „od”, przypisany – „moje” / „nieprzypisane”, czas ostatniego zdarzenia, silnik, komputer, konto, tekst), licznikiem i doładowywaniem starszych; kliknięcie komputera albo konta filtruje listę;
  - zaznaczanie wielu alertów: „Weź do analizy”, „Zamknij” (jeden powód dla wszystkich), „Otwórz ponownie”;
  - szczegóły: przypisanie analityka („Biorę do analizy” przypisuje do siebie), oś czasu (zmiany stanu, przypisania, notatki – także automatyczne zamknięcia przez system), notatki, powiązane alerty (ten sam komputer albo konto, ±24 h), przycisk „zdarzenia z tego komputera ±15 min” w Mímirze;
  - każda zmiana trafia na oś czasu alertu i do audytu panelu; przypisać można tylko aktywnego analityka albo administratora.
- **Obsługiwany podzbiór Sigmy:** `logsource` Windows (service: security, system, application, sysmon, powershell…; category: process_creation – Sysmon 1 i Security 4688, ps_script, network_connection, file_event, dns_query, registry_set), selekcje (mapy, listy, słowa kluczowe), modyfikatory `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `exists`, maski `*`/`?`, warunki `and/or/not`, `1 of`/`all of`. Reszta (agregacje `| count()`, `timeframe`, inne modyfikatory) jest jawnie odrzucana – progi definiuje się rozszerzeniem `vardr.threshold`.
- **Rozszerzenia Vardra** (klucz `vardr:` w regule): `mode` (stream / index_query / both), `group_by`, `suppress`, `instructions` (pokazywane w alercie i na Discordzie; zmienne `{{Pole}}`, np. `{{SubjectUserName}}`, `{{Computer}}`, są zastępowane wartościami ze zdarzenia przy tworzeniu alertu), `enabled`, `threshold`.
- **Reguły progowe** (`vardr.threshold`: `count`, `window`, opcjonalnie `distinct`): alert powstaje, gdy w dowolnym oknie `window` (liczonym po czasie zdarzenia, więc spóźnione zdarzenia z bufora agenta też się liczą) jest co najmniej `count` pasujących zdarzeń – albo `count` różnych wartości pola `distinct` – z tym samym kluczem `group_by`. Do alertu trafiają wszystkie zdarzenia z tego okna oraz – łańcuchowo – kolejne (i wcześniejsze) zdarzenia tego klucza, dopóki przerwa nie przekroczy `suppress` (co najmniej długość okna); zdarzenia już będące w alercie przedłużają łańcuch, nawet gdy samo okno wypadło z pamięci. W instrukcji działają dodatkowo `{{count}}`, `{{window}}` i `{{values}}` (lista różnych wartości). Stan progów jest zapisywany razem z alertami (`gjallarhorn.threshold_events`), więc restart detektora nie zeruje liczników. Silnik w locie trzyma zdarzenia klucza z okna + max(`suppress`, 1 h); zdarzenie spóźnione bardziej liczy się tylko z tym, co zostało w pamięci – takie przypadki nadrabia silnik zapytań. Przykłady: [brute force](rules/windows/security_brute_force_logon.yml), [password spraying](rules/windows/security_password_spraying.yml).
- **Utrata łączności z agentem** (reguła wbudowana, nie Sigma): detektor co 30 s porównuje ostatni heartbeat agentów z progiem ich grupy – panel → *Grupy agentów* → „Alarm po utracie łączności” (5–10 080 min; puste = bez alarmu, np. stacje wyłączane na noc). Jedna przerwa = jeden alert (`engine = system`); gdy agent wróci, alert zamyka się sam z adnotacją. Agenci wycofani (wszystkie certyfikaty unieważnione) są pomijani. Uzupełnia ją reguła Sigma na zatrzymanie usługi agenta albo Sysmona (System 7036/7031/7034) – zdarzenie dociera po ponownym starcie agenta i mówi, kiedy dokładnie usługę zatrzymano.
- **Reguły w repozytorium (scenariusze z roadmapy, sekcja 11):** brute force (4625, Kerberos 4771), password spraying, dodanie do grupy uprzywilejowanej, wyczyszczenie dziennika Security (1102) i innych dzienników (System 104), PowerShell z zakodowanym poleceniem i podejrzane skrypty (4104), usługa z podejrzanej lokalizacji (7045), nowe konto (4720), zatrzymanie usług bezpieczeństwa, utrata łączności z agentem. Urządzenia sieciowe (etap 6): seria nieudanych logowań do VPN i panelu FortiGate oraz do routera MikroTik – opis w sekcji „Kolektor syslog i dekodery”. Entra ID czeka na integrację.

### Kolektor syslog i dekodery (etap 6)

```
FortiGate, MikroTik, NAS… ──syslog UDP/TCP 514──► siem-collector ──mTLS:8443──► siem-ingest ──► (dalej jak zdarzenia agentów)
                                                  (bufor dyskowy, ponowienia)
siem-normalizer: nagłówek syslog (RFC 3164 / 5424 / sam <PRI>) → pierwszy pasujący dekoder → pola zdarzenia
```

**Kolektor** (`siem-collector`) to ten sam kod co agent Windows: bufor dyskowy, ponawianie, certyfikat klienta, heartbeat, odnawianie certyfikatu. Działa na Linuksie (w laboratorium jako kontener na VM) i przyjmuje syslog po UDP i TCP (ramki z długością albo zakończone nową linią). Nadawca (`syslog.peer`) jest zapamiętywany przy zdarzeniu. Przerwa łączności z serwerem nie gubi logów w granicach bufora (sprawdzone: 50 wiadomości przy zatrzymanym `siem-ingest` dotarło po jego starcie).

- Wdrożenie: `deploy/lab/deploy.sh collector`, a potem raz `deploy/lab/collector-enroll.sh [grupa]`. Skrypt tworzy na VM jednorazowy token (w bazie tylko skrót, wpis w audycie), rejestruje kolektor i uruchamia usługę.
- Konfiguracja: `collector/collector.yaml`. Najważniejsze pola to `syslog.udp` / `syslog.tcp` (adresy nasłuchu), `syslog.allow` (dozwolone sieci nadawców), `buffer.max_mb` i `buffer.on_full` (`drop_oldest` albo `pause`).
- Strefa czasu nagłówków bez strefy (RFC 3164): `SIEM_SYSLOG_TZ` (domyślnie Europe/Warsaw) w normalizatorze i panelu.

**Konfiguracja urządzeń**

MikroTik RouterOS 7 (od 7.17; starsze wersje: `bsd-syslog=yes` zamiast `remote-log-format`):

```
/system logging action add name=vardr target=remote remote=<adres kolektora> remote-port=514 remote-log-format=syslog syslog-time-format=bsd-syslog syslog-facility=local0
/system logging add topics=info action=vardr
/system logging add topics=warning action=vardr
/system logging add topics=error action=vardr
/system logging add topics=critical action=vardr
/system logging add topics=account action=vardr
```

FortiGate (FortiOS 7):

```
config log syslogd setting
    set status enable
    set server "<adres kolektora>"
    set port 514
    set format default
end
```

**Dekodery** to definicje YAML. Wbudowane leżą w [internal/decode/builtin](internal/decode/builtin), własne tworzy się w panelu.

- `match`: kiedy dekoder pasuje. Wszystkie podane warunki muszą być spełnione, a z listy `any` co najmniej jedna alternatywa. Dostępne warunki:
  - `peer` (sieci nadawców),
  - `host`,
  - `app` / `app_regex` (program z nagłówka),
  - `contains`,
  - `regex` (treść).
- `parser`: `kv`, `json`, `csv` (z `separator` i `columns`; spacja pasuje też do logów W3C/IIS), `regex` (lista wzorców z grupami nazwanymi i stałymi `set`) albo `none`.
- `fields`: przypisanie pól treści do pól zdarzenia:
  - `user.name`, `source.ip`, `host.name`, `event.action`, `event.outcome`, `event.code`, `process.name`, `message`…;
  - pierwsze niepuste z listy wygrywa.
- `outcome`: `failure` / `success` z wartości pola.
- `time`: czas zdarzenia z pól treści.
- `samples`: przykładowe wiadomości. Są wymagane przy zapisie w panelu i muszą się dekodować.
- Dekodery sprawdzane są po kolei: wyższy `priority` pierwszy. Wiadomość bez dekodera trafia jako `syslog.generic` z nagłówkiem i treścią. Treść niepasująca do parsera (np. zepsuty JSON) trafia do kwarantanny.
- Wbudowane:
  - **FortiGate**: ruch, zdarzenia, VPN, UTM, czas z `date`/`time`/`tz`.
  - **MikroTik RouterOS 6 i 7**: logowania udane i nieudane, zmiany konfiguracji, DHCP, zapora, Wi-Fi, zmiany czasu, interfejsy. RouterOS 7 nie wysyła tematów w nagłówku, więc router jest rozpoznawany po tożsamości `MikroTik` albo po treści. Router o innej tożsamości dopisz w `match.any` jako `peer`.
- Reguły detekcji dla urządzeń: `logsource.product: fortigate` / `mikrotik` (zbiory `fortinet.fortigate`, `mikrotik.routeros`) i pola ECS (`event.action`, `event.outcome`, `source.ip`, `user.name`…). Reguły w repozytorium:
  - [MikroTik – seria nieudanych logowań](rules/network/mikrotik_login_brute_force.yml),
  - [FortiGate – seria nieudanych logowań do VPN](rules/network/fortigate_vpn_brute_force.yml),
  - [FortiGate – nieudane logowania administratora](rules/network/fortigate_admin_login_failures.yml).

**Panel → Dekodery** pokazuje działający zestaw w kolejności sprawdzania.

- **Test** dekoduje próbki:
  - wklejone albo wczytane z bazy („Nierozpoznane” to ostatnie `syslog.generic`, „Obsłużone przez ten” to wiadomości danego dekodera);
  - zestawem, w którym edytowana definicja zastępuje swój odpowiednik, więc widać też przesłonięcie przez dekoder o wyższym priorytecie;
  - wynik pokazuje nagłówek, pola zdarzenia, wszystkie pola treści, wiadomości bez pasującego wzorca i trafiające do kwarantanny.
- **Zapis** (administrator) tworzy nową rewizję z historią i różnicami.
- Własna definicja o id wbudowanego zastępuje go. „Przywróć wersję wbudowaną” cofa tę zmianę.
- Wyłączenie dekodera albo usunięcie własnego wymaga powodu i hasła, bo reguły danego produktu przestają widzieć te wiadomości.
- Zmiany trafiają do normalizatorów przez magazyn NATS KV `SIEM_DECODERS` w ciągu kilku sekund, bez restartu. Panel wyrównuje magazyn do bazy przy starcie i co 5 min.
- Zdarzenia już zapisane się nie zmieniają.

**Panel → Kwarantanna** pokazuje zdarzenia, których nie udało się znormalizować albo zapisać: grupy według źródła i powodu oraz najnowsze wpisy z oryginałem.

- Po poprawce dekodera albo programu administrator zleca **ponowne przetworzenie** grupy albo wszystkiego z filtra (do 10 000 wpisów w zleceniu).
- Panel wysyła wpisy częściami do normalizatora (NATS request-reply, `siem.reprocess`). Normalizator dekoduje je bieżącym kodem i publikuje odzyskane zdarzenia w `SIEM_EVENTS`, więc trafiają do bazy i do detekcji jak nowe:
  - czas przyjęcia to chwila ponownego przetworzenia;
  - pierwotny czas jest w `siem.quarantined_at`, a numer zlecenia w `siem.reprocess_job`.
- Oryginały nie wracają do `SIEM_RAW`, więc archiwum NIS2 nie dostaje duplikatów.
- Wynik każdego wpisu (odzyskany albo nadal błędny, z nowym powodem) i postęp zlecenia są zapisywane w Sadze. Kolejne zlecenia pomijają wpisy już odzyskane.
- Wpisy odrzucone przy zapisie do ClickHouse i ze ścieżki odtwarzania nie są przetwarzane ponownie.

**Instalacje sprzed etapu 6** wymagają jednorazowo dwóch zmian:

- Kolumny kwarantanny (przed wdrożeniem nowego `siem-writer`):

  ```
  docker compose exec -T clickhouse clickhouse-client -q "ALTER TABLE siem.quarantine ADD COLUMN IF NOT EXISTS peer String DEFAULT ''"
  docker compose exec -T clickhouse clickhouse-client -q "ALTER TABLE siem.quarantine ADD COLUMN IF NOT EXISTS truncated Bool DEFAULT false"
  ```

- NATS: `max_file_store` musi być większy od sumy rezerwacji kolejek (`SIEM_QUEUE_*_MAX_MB` i kopie dla odtwarzania). Bez zapasu JetStream odmawia utworzenia magazynu dekoderów, z błędem „insufficient storage resources”. W laboratorium jest 21 GB, czyli 20 GB kolejek i 1 GB zapasu. Zmiana limitu wymaga `docker compose restart nats`, bo HUP go nie przeładowuje.

**Symulator FortiGate:** `go run ./tools/cmd/fortisim -target <kolektor>:514 -scenario mix` wysyła logi w formacie FortiOS.

- Scenariusze:
  - `traffic` – ruch,
  - `vpn-ok`, `vpn-brute`, `vpn-spray` – logowania do VPN,
  - `admin-brute` – logowania administratora,
  - `utm` – IPS i antywirus,
  - `mix` – wszystko po trochu.
- Opcje:
  - `-proto tcp`,
  - `-header rfc5424` albo `rfc3164`,
  - `-attacker <adres>`,
  - `-dry` (tylko wypisanie).

### Tożsamości osób (etap 7a)

Każde zdarzenie z kontem dostaje **osobę** – kolumnę `user_identity` (pole `user.identity` w regułach, `identity:` albo `osoba:` w Mímirze). Klucz to nazwa konta bez domeny, małymi literami, więc to samo konto w AD (`AZUJO\jkowalski`), w Entra ID (`jkowalski@azujo.pl`), na VPN FortiGate i na routerze (`jkowalski`) to jedna osoba. Reguły mogą liczyć progi i grupować po osobie niezależnie od źródła.

- **Konta techniczne** nie mają osoby:
  - konta komputerów (`…$`);
  - SYSTEM i usługi wbudowane, także w polskiej wersji Windows (`ZARZĄDZANIE NT`, `USŁUGA LOKALNA`);
  - konta wirtualne usług i surowe SID.
- **Domeny organizacji** (panel → Tożsamości) to nazwy NetBIOS i DNS, np. `azujo`, `azujo.centrala`, `azujo.pl`.
  - Konta z innych domen zostają osobnymi tożsamościami z domeną: lokalne konta komputerów (`desktop-1\admin`) i goście (`partner@obca.pl`).
  - Pusta lista oznacza, że każda domena należy do organizacji.
- **Konta wspólne urządzeń** (ta sama zakładka; domyślnie `admin`, `administrator`, `root`, `guest`): takie konto bez domeny – `admin` na routerze MikroTik czy FortiGate – dostaje tożsamość z nazwą urządzenia (`mikrotik\admin`). Korelacje nie łączą wtedy prób na różnych urządzeniach ani z domenowym `AZUJO\admin`. Konto na urządzeniu z właścicielem: alias `mikrotik\admin` → osoba. „Sprawdź konto” przyjmuje też nazwę urządzenia.
- **Aliasy** przypisują inne nazwy do osoby, np. login VPN `j.kowalski` → `jkowalski`.
  - Kluczem aliasu może być konto, `DOMENA\konto` albo UPN.
  - Aliasy nie tworzą łańcuchów.
  - Zakładka „Podpowiedzi” wskazuje osoby różniące się tylko kropkami, podkreśleniami lub myślnikami („połącz” dodaje aliasy).
  - Zakładka „Domeny organizacji” pokazuje domeny kont widziane w zdarzeniach z 7 dni; domeny spoza listy są pomarańczowe, a strona ostrzega o nich. Pomyłka w domenach po cichu rozdziela osoby: np. bez `azujo` (NetBIOS) konto `AZUJO\jan` staje się `azujo\jan`, osobno od `jan@azujo.pl`.
- Zakładka „Osoby” pokazuje najaktywniejsze osoby: źródła, konta, liczbę zdarzeń i nieudanych prób, komputery.
- Konfiguracja trafia do normalizatorów i archiwizatora przez NATS KV `SIEM_IDENTITY` w ciągu kilku sekund. Panel wyrównuje ją przy starcie i co 5 min. Zdarzenia już zapisane się nie zmieniają.
- Instalacje sprzed etapu 7 – jednorazowo, przed wdrożeniem nowego `siem-writer` i `siem-detector`:

  ```
  docker compose exec -T clickhouse clickhouse-client -q "ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS user_identity LowCardinality(String) DEFAULT '' AFTER time_quality"
  docker compose exec -T clickhouse clickhouse-client -q "ALTER TABLE siem.events_replay ADD COLUMN IF NOT EXISTS user_identity LowCardinality(String) DEFAULT '' AFTER time_quality"
  ```

### Entra ID i korelacje międzyźródłowe (etap 7)

```
Microsoft Graph ──HTTPS──► siem-connector ──mTLS:8443──► siem-ingest ──► (dalej jak zdarzenia agentów)
(auditLogs/signIns, directoryAudits)   (kursor czasu, bufor dyskowy)
```

**Konektor** (`siem-connector`) to ten sam szkielet co kolektor syslog (`agent/internal/hostagent`): bufor, mTLS, heartbeat i rejestracja tokenem. Działanie:
- co minutę pobiera z Microsoft Graph logowania i zmiany w katalogu Entra ID;
- trzyma kursor czasu z zakładką 15 min, bo logi pojawiają się w Graph z opóźnieniem;
- zaległości (pierwszy start, długa przerwa) nadrabia oknami godzinowymi;
- przy limicie zapytań (429) czeka tyle, ile każe `Retry-After`;
- odnawia token aplikacji;
- identyfikator rekordu z Graph jest identyfikatorem zdarzenia, więc ponowne pobranie po restarcie nie tworzy duplikatów.

Konfiguracja to `connector/connector.yaml`, sekcja `entra` (sekret aplikacji w osobnym pliku). Prawdziwy tenant wymaga:
- rejestracji aplikacji w Entra ID z uprawnieniami aplikacji `AuditLog.Read.All` i `Directory.Read.All` oraz zgodą administratora;
- licencji Entra ID P1 lub P2 – bez niej logowania nie są dostępne w Graph, zostają tylko zmiany w katalogu.

**Symulator Microsoft Graph** (`tools/cmd/entrasim`, usługa `entrasim` w laboratorium) to API zgodne z Graph:
- token OAuth2, filtr czasu, stronicowanie `@odata.nextLink`;
- opóźnienie pojawiania się logów i co 7. zapytanie z odpowiedzią 429;
- rekordy w kształcie zasobów `signIn` i `directoryAudit`.

Konektor rozmawia z nim tak samo jak z Microsoftem, a prawdziwy tenant to tylko inne `tenant_id`, `client_id`, sekret i usunięte `login_url` / `graph_url`. Scenariusze na VM:

```
curl -X POST 'http://127.0.0.1:8099/sim/scenario?name=spray&attacker=185.220.101.66'
curl -X POST 'http://127.0.0.1:8099/sim/scenario?name=foreign&user=anowak&attacker=203.0.113.210'
```

Nazwy scenariuszy:
- `normal`,
- `spray`,
- `brute`,
- `success-after-failures`,
- `foreign`,
- `mfa-fatigue`,
- `admin-role`.

Wdrożenie: `deploy/lab/deploy.sh connector`, a raz `deploy/lab/service-enroll.sh connector`. Skrypt rejestruje konektor, tworzy wspólny sekret i kieruje konektor na symulator.

**Dekodery** (wbudowane):
- `entra-signin` → `azure.signinlogs`:
  - wynik z kodu błędu (0 – udane, 50126 – złe hasło, 50053 – blokada, 500121 – odrzucone MFA…), kod w `event.code`;
  - kraj i miasto z lokalizacji Microsoftu (`source.geo.country_iso_code`);
  - aplikacja i protokół klienta (`user_agent.client`, np. IMAP4 – stare uwierzytelnianie).
- `entra-audit` → `azure.auditlogs`:
  - akcja, konto wykonujące, konto zmieniane (`user.target.name`), nadana rola (`azure.role`).

Reguły Sigma: `logsource.product: azure`, `service: signinlogs` albo `auditlogs`. Dekodery mają też stałe pola `set` i `outcome.otherwise`, a tablice JSON są rozwijane również z indeksem (`targetResources.0.userPrincipalName`).

**Korelacje międzyźródłowe** działają po osobie (`user.identity`, sekcja „Tożsamości osób”):
- **Password spraying z jednego adresu (wiele źródeł)** – reguła Sigma ([rules/cross](rules/cross/password_spraying_multi_source.yml)):
  - nieudane logowania co najmniej 5 różnych osób z jednego adresu w 10 min, łącznie w AD, Entra ID, na VPN FortiGate i routerze;
  - działa w obu silnikach.
- **Udane logowanie po serii nieudanych (wiele źródeł)** – reguła wbudowana:
  - udane logowanie osoby poprzedzone co najmniej 5 nieudanymi w ciągu 30 min, w dowolnych źródłach (np. próby na VPN, a potem wejście do chmury);
  - w alercie jest udane logowanie i próby z serii.
- **Logowanie z nowego kraju** – reguła wbudowana:
  - udane logowanie z kraju, z którego osoba w ostatnich 30 dniach się nie logowała;
  - osoby bez historii są pomijane;
  - na razie korzysta z krajów Entra ID; VPN wymaga lokalnej bazy GeoIP.

Reguły wbudowane `siem-detector` ocenia co minutę zapytaniami do ClickHouse:
- okno 15 min, przy starcie 2 h wstecz;
- konto `siem_detector`, także w trybie tylko „w locie”, o ile ustawione jest `SIEM_DETECTOR_CH_PASSWORD`;
- silnik w alercie to „korelacja”;
- korelację można wyłączyć z panelu jak regułę Sigma (powód, hasło, audyt).

**„Powiązane alerty”** na stronie alertu szukają po komputerze, koncie i osobie: alert z Entra ID (`jan@azujo.pl`) pokazuje alerty AD tej samej osoby (`AZUJO\jan`). Detektor zapisuje osobę w alercie od wersji z 17.10.2026; starsze alerty mają ją tylko w korelacjach.

**Cisza źródła** – reguła wbudowana (wyłączana z panelu jak korelacje), co 5 min w ClickHouse:
- źródło to urządzenie syslog (router, zapora – po nazwie urządzenia) albo połączenie z chmurą (konektor i zbiór, np. `azure.signinlogs`; komputer w logowaniu Entra to urządzenie użytkownika, nie źródło); zdarzenia Windows pilnuje heartbeat agenta;
- alert, gdy źródło milczy dłużej niż jego najdłuższa przerwa z ostatnich 7 dni + 1 h (najmniej `SIEM_SOURCE_SILENCE_MIN`, domyślnie 1 h): zapora logująca bez przerwy – po ok. 2 h, router cichy nocami – dopiero po przerwie dłuższej niż zwykła noc;
- źródła rzadkie (zdarzenia w mniej niż 24 godzinach tygodnia) są pomijane;
- jedna przerwa = jeden alert; gdy zdarzenia wrócą, alert zamyka się sam (z powiadomieniem).

Przy błędzie dostępu do Graph (zły sekret, brak zgody administratora, brak licencji) panel pokazuje przy konektorze kanał `entra-signin` / `entra-audit` ze stanem „brak dostępu” i treścią błędu. Graph v1.0 zwraca tylko logowania interaktywne; nieinteraktywne są w API beta.

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
- **Miejsce na dysku:** archiwum zajmuje ok. 100 B na zdarzenie, czyli ~85 GB na dobę przy 10 000 zdarzeń/s. Powinno więc leżeć na osobnym dysku: `SIEM_ARCHIVE_PATH` w `.env`, np. `/srv/vardr/archive`.
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

**Dysk archiwum (jednorazowo, wymaga sudo):** osobny dysk (w laboratorium 150 GB, `/dev/sdb`) zamontowany w `/srv/vardr`, z katalogami `archive` i `backup` należącymi do `siem` (uid 1000):

```bash
sudo mkfs.ext4 -L vardr-data /dev/sdb
sudo mkdir -p /srv/vardr && echo 'LABEL=vardr-data /srv/vardr ext4 defaults,noatime,nofail 0 2' | sudo tee -a /etc/fstab && sudo mount -a
sudo mkdir -p /srv/vardr/archive /srv/vardr/backup && sudo chown -R 1000:1000 /srv/vardr && sudo chmod 750 /srv/vardr/archive /srv/vardr/backup
```

W `.env` ustaw `SIEM_ARCHIVE_PATH=/srv/vardr/archive` (i `SIEM_BACKUP_DIR=/srv/vardr/backup`, jeśli kopie mają leżeć gdzie indziej niż domyślnie). Laboratorium zostało przy dysku zamontowanym w `/srv/heimdall` (nazwa sprzed zmiany nazwy projektu) – ścieżki ustawia jego `.env`. Dzięki `nofail` brak dysku nie blokuje startu VM, a dwie blokady chronią przed pisaniem archiwum na dysk systemowy:

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

Każde zlecenie, anulowanie i nieudane potwierdzenie hasłem trafia do audytu, a błędne hasło liczy się do blokady konta jak przy logowaniu. Stan zgodności pokazuje „archiwizacja WYŁĄCZONA” i „zaplanowane osłabienie polityki”, a Grafana ma alerty `vardr-archive-disabled` i `vardr-archive-policy-scheduled`. Metryki: `siem_archive_policy_enabled`, `siem_archive_policy_scheduled_weakening`, `siem_archive_policy_retention_days`, `siem_archive_skipped_total{reason}`.

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

Administrator zleca eksport w panelu: zakładka *Urd → Eksport dla audytora*, zakres pełnych godzin archiwizacji (do 31 dni) i obowiązkowy powód. Archiwizator przygotowuje paczkę `urd-eksport-<nr>-<od>-<do>.tar` w `/srv/vardr/export` (`SIEM_ARCHIVE_EXPORT_PATH`). Paczkę da się w całości odczytać i sprawdzić **bez Vardra**, np. przy zgłoszeniu incydentu do CSIRT albo organu nadzoru. Zawiera:

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

Polecenie Vardra sprawdza to samo co skrypt, czyli:

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

### Start po restarcie VM

`deploy.sh config` dopisuje do crontaba użytkownika `siem` wpis `@reboot ~/siem-lab/boot.sh`, który 30 s po starcie systemu uruchamia `docker compose up -d` (dziennik: `~/siem-lab/boot.log`). Sama polityka `restart: unless-stopped` nie wystarczyła: po wyłączeniu VM przyciskiem w Proxmoxie Docker nie podniósł NATS ani Prometheusa.

### Klucz sortowania zdarzeń (od etapu 8)

`siem.events` jest sortowana po `(event_dataset, toStartOfHour(ingested), host_name, timestamp, event_id)`. Silnik zapytań i korelacje czytają nowe zdarzenia po czasie przyjęcia, a dawny klucz bez `ingested` zmuszał je do czytania całej dziennej partycji. Instalację z dawnym kluczem przenosi `bash clickhouse/events-order.sh [prefiks_agentów_do_pominięcia]` w `~/siem-lab`. Skrypt na czas kopii zatrzymuje writer (zdarzenia czekają w NATS), porównuje liczbę wierszy w każdej partycji i zostawia starą tabelę jako `siem.events_old`.

### Tabela logowań dla korelacji (od etapu 8)

Korelacje („udane logowanie po serii nieudanych”, „logowanie z nowego kraju”) liczą się na `siem.auth_events`, a nie na `siem.events`. Widok zmaterializowany odkłada do niej przy zapisie tylko logowania (udane i nieudane, z ustaloną osobą). Wcześniej korelacja co minutę czytała wszystkie zdarzenia Windows z ostatnich 1,5 h: przy 7000 zdarzeń/s było to ok. 48 mln wierszy na przebieg, teraz ok. 100 tys. Udane logowania Windows (4624, najliczniejsze) żyją w tabeli 1 dzień, reszta tyle co zdarzenia. Na istniejącej instalacji tabelę zakłada (i dopisuje logowania z całej retencji) polecenie w `~/siem-lab`:

    docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/03-auth-events.sh

Warunki logowań w skrypcie muszą być takie same jak w `server/internal/detector/correlate.go` – pilnuje tego test korelacji.

### Kopie zapasowe

Kopie wykonuje usługa **siem-backup** (kontener `backup`) według ustawień z panelu: **Administracja → Kopie zapasowe**. Opis ustawień: [docs/operacje.md](docs/operacje.md#kopie-zapasowe).

- **Harmonogram:** co kilka godzin, codziennie albo co tydzień.
- **Zawartość:**
  - baza Saga (zrzut sprawdzany przez `pg_restore --list` przed zaszyfrowaniem);
  - `certs/` z kluczem CA agentów i `.env`;
  - przyrosty archiwum NIS2;
  - dane Grafany.
- **Retencja:** dni i najwyższa liczba kopii, osobno lokalnie i w miejscu docelowym.
- **Miejsce docelowe:**
  - SFTP: klucz SSH wygenerowany przez usługę, własny klucz albo hasło;
  - SMB;
  - S3.

Każda kopia to **jedna zaszyfrowana paczka** `vardr-RRRRMMDD-GGMM-k<id>.tar.gpg` (gpg, AES-256). Da się ją odszyfrować na dowolnym Linuksie albo na Windows z Gpg4win, bez Vardra. `k<id>` w nazwie to identyfikator hasła, którym ją zaszyfrowano.

**Hasło kopii** (uruchamia administrator na VM, w `~/siem-lab`):

```bash
./backup.sh haslo init    # pierwsze hasło – pokazywane raz; zapisz je poza serwerem
./backup.sh haslo pokaz   # pokaż obecne hasło
./backup.sh haslo zmien   # nowe hasło dla kolejnych kopii (stare kopie otwiera tylko stare hasło)
./backup.sh               # kopia teraz (to samo co „Zrób kopię teraz” w panelu)
```

Hasło leży w `~/.vardr-backup.pass` (tylko dla właściciela), poza katalogiem stosu i poza samą kopią; panel go nie zna. **Bez hasła kopii nie da się odtworzyć** – po utracie VM potrzebne jest hasło zapisane przez administratora. Bez hasła kopie nie powstają: panel pokazuje ostrzeżenie, a alert „brak udanej kopii” zgłasza to po 26 h.

**Hasła i klucze do miejsca docelowego** wpisuje się w panelu. Panel szyfruje je kluczem publicznym usługi kopii (NaCl), więc po zapisie nie odczyta ich ani panel, ani baza – można je tylko zastąpić. Przy logowaniu SFTP kluczem usługi panel pokazuje klucz publiczny do dopisania w `authorized_keys` na serwerze kopii. Klucz serwera kopii jest zapamiętywany przy pierwszym połączeniu, a jego zmiana zatrzymuje wysyłkę.

**W miejscu docelowym:**

- `config/` – paczki kopii;
- `urd/` – przyrosty archiwum NIS2: nowe segmenty i manifesty od poprzedniej wysyłki, zaszyfrowane tym samym hasłem. Wygasają tylko po dniach.

Alert „kopia nie trafiła poza VM od ponad 26 h” pilnuje wysyłki. Stan usługi (klucze, `known_hosts`) jest w `~/siem-lab/backup-state`.

**Przywracanie z panelu** (zakładka *Przywracanie*): wybór kopii (lokalnej albo z miejsca docelowego), sprawdzenie zawartości, przywrócenie bazy Saga z konfiguracją i/lub danych Grafany. Przed przywróceniem powstaje kopia obecnego stanu. Usługi zatrzymuje i przywraca `restore.sh --zlecenie` (cron co minutę). Szczegóły: [docs/operacje.md](docs/operacje.md#kopie-zapasowe).

**Odtworzenie całego systemu na czystej VM** (Docker zainstalowany, stos skopiowany `deploy.sh config` i usługi zbudowane):

```bash
scp <użytkownik>@<serwer kopii>:<katalog kopii>/config/vardr-….tar.gpg .
rsync -a <użytkownik>@<serwer kopii>:<katalog kopii>/urd/ urd/   # opcjonalnie: archiwum NIS2
./restore.sh vardr-….tar.gpg urd/
```

`restore.sh` pyta o hasło kopii, przywraca to, co jest w kopii (`certs/` i `.env`, bazę Saga, dane Grafany), z drugim argumentem także archiwum NIS2, a potem uruchamia stos. Kopia nie zawiera zdarzeń z ClickHouse (kilka dni) – można je odtworzyć z archiwum w panelu (Urd → Odtworzenie).

### Alerty (Grafana)

Do czasu modułu alertów (Gjallarhorn, etap 4) awarie zgłasza Grafana. Reguły są w `grafana/provisioning/alerting/vardr.yaml`, folder SIEM, grupa „Vardr – zdrowie”:

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

Domyślnie generator ma 3500 kont i 0,2% nieudanych logowań (zwykły dzień firmy); `-failures 5` to ciągły brute force na wszystkich kontach (scenariusz przeciążenia detekcji). Zdarzenia z prefiksem `agt-load-` nie trafiają do archiwum (`SIEM_ARCHIVE_EXCLUDE_AGENTS`). Po teście: `cd ~/siem-lab && bash loadtest-cleanup.sh` – usuwa zdarzenia, alerty, stan progów i agentów generatora (w tej kolejności, inaczej silnik zapytań odtworzy alerty z danych, które zostały). Monitor na czas testu (`loadtest-monitor.sh`), sprzątanie po dużym teście (`loadtest-droppart.sh`) i pełna procedura: [docs/testy-obciazeniowe.md](docs/testy-obciazeniowe.md).

Zasady skalowania, obsługa przeciążenia, pomiary i znane ograniczenia: [docs/ROADMAP.md – załącznik E](docs/ROADMAP.md#załącznik-e-skalowanie-i-przeciążenie).
