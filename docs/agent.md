# Agent Windows – Huginn

Agent `vardr-agent` zbiera zdarzenia z dzienników Windows i wysyła je do serwera po mTLS, z buforem dyskowym, ochroną przed zatrzymaniem i limitami zasobów. Polecenia, flagi i konfiguracja: [programy.md](programy.md). Rejestracja agentów tokenem i paczki instalacyjne: [panel.md](panel.md).

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

**Gotowy skrypt:** [deploy/windows/vardr-gpo.ps1](../deploy/windows/vardr-gpo.ps1) – uruchomiony na kontrolerze domeny (administrator domeny) tworzy i podłącza GPO „Vardr - polityka audytu” (cała domena: zaawansowana polityka inspekcji, linia poleceń w 4688, logowanie bloków PowerShell, dziennik Security 256 MB) oraz „Vardr - dzienniki DC” (Security 1 GB na kontrolerach domeny). Można go uruchamiać wielokrotnie. Sprawdzony w laboratorium (Windows Server 2025, Windows 11): nieudane logowania (4625, 4776, 4768), zmiany kont i grup (4720, 4732, 4733, 4726), procesy z linią poleceń (4688) i PowerShell (4104) docierają do Mímira.

**Sysmon:** [deploy/windows/sysmon.ps1](../deploy/windows/sysmon.ps1) instaluje albo aktualizuje Sysmona (program z podpisem Microsoftu, konfiguracja domyślnie SwiftOnSecurity albo z udziału `-Source \\domena\NETLOGON\sysmon`). Nadaje się na skrypt startowy komputera w GPO i można go uruchamiać wielokrotnie. Agent (od 0.6.2) niczego nie instaluje – raportuje stan Sysmona (wersja, skrót konfiguracji), a w grupie agentów z opcją „Wymagany Sysmon” panel zgłasza komputery bez Sysmona, z zatrzymanym Sysmonem albo z inną konfiguracją niż większość grupy.

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
