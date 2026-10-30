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

**Język.** Polecenia `vardr-agent` piszą po polsku albo po angielsku – według języka Windows (wymuszenie: zmienna `VARDR_LANG=pl` albo `en`). W tym języku są też ostrzeżenia w `status` i w panelu. Log agenta i wpisy w Podglądzie zdarzeń są po angielsku.

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

Każde wydanie agenta potrzebuje nowego numeru wersji (`const version` w `agent/cmd/vardr-agent/version.go`). Przebudowany instalator tej samej wersji `wixl` instaluje obok poprzedniego jako drugi produkt (nie obsługuje `AllowSameVersionUpgrades`).

### Automatyczne aktualizacje (od wersji 0.10)

Grupa agentów ma opcję *Automatyczne aktualizacje agenta* (panel → Grupy agentów; domyślnie wyłączona). Włączenie potwierdza się hasłem i trafia do audytu: panel może wtedy uruchomić instalator na wszystkich komputerach grupy – to takie samo zaufanie jak do konta, które wdraża MSI przez GPO.

- Konfiguracja grupy podaje wersję, rozmiar i sumę SHA-256 bazowego instalatora z serwera (`agent-dist/vardr-agent.msi` i `AGENT_VERSION` – paczka instalacyjna serwera albo `deploy.sh agent`).
- Agent starszy niż ta wersja czeka losowo do 30 minut (pobrania rozłożone w czasie), pobiera instalator z panelu przez mTLS (`/enroll/v1/agent.msi`, tylko dla grup z włączoną opcją), sprawdza rozmiar i sumę, zapisuje go w katalogu stanu (dostępnym tylko dla administratorów i SYSTEM) i uruchamia `msiexec /i … /qn`. Dalej jak przy ręcznej aktualizacji: usługa wraca w nowej wersji z tą samą rejestracją, a ochrona zgłasza aktualizację instalatorem (alert, gdy agent nie wróci w 15 min).
- Nigdy nie obniża wersji. Nieudana próba danej wersji powtarza się najwcześniej po 6 godzinach; błąd i ścieżka dziennika `msiexec` są na stronie agenta w panelu i w `vardr-agent status`.
- Strona agenta pokazuje stan: zaplanowana, trwa instalacja, nieudana, zaktualizowano (z wersji → do wersji).
- Agenci starsi niż 0.10 nie mają tej funkcji – pierwszą aktualizację do 0.10 robi się ręcznie (MSI, GPO).
- **Agent Linux (od 0.12):** konfiguracja grupy podaje też program dla każdej architektury (`agent-dist/vardr-agent-linux-amd64` i `-arm64`, ta sama wersja z `AGENT_VERSION`). Agent pobiera go z `/enroll/v1/agent-linux/<arch>`, sprawdza sumę i uruchamia go jako przejściową usługę systemd (`systemd-run`, poza ograniczeniami usługi agenta) z poleceniem `apply-update`. Ta zapisuje poprzedni program jako `/usr/local/sbin/vardr-agent.previous`, podmienia program i plik usługi, uruchamia usługę ponownie i czeka do 3 minut, aż nowa wersja potwierdzi start (i działa jeszcze 15 s). Bez potwierdzenia przywraca poprzednią wersję, a błąd widać w panelu. Dziennik: `/var/lib/vardr-agent/update/update-<wersja>.log` i `journalctl -u 'vardr-agent-update-*'`. Agenta 0.11 aktualizuje się do 0.12 ręcznie (`sudo ./vardr-agent upgrade`).

### Ochrona przed zatrzymaniem i deinstalacją (od wersji 0.7)

Pełnej blokady nie ma: lokalny administrator zawsze może zmienić uprawnienia usługi, a konto SYSTEM może wszystko. Cel to **utrudnić i wykryć**. Ochronę włącza grupa agentów (panel → Grupy agentów → „Ochrona agenta”, domyślnie włączona). Agent bez konfiguracji z panelu jest bez ochrony.

- **Uprawnienia usługi.** Administrator sprawdzi stan usługi, uruchomi ją i zrestartuje agenta (`vardr-agent restart` – polecenie 128 do usługi). Nie może jej zatrzymać, wstrzymać, przekonfigurować ani usunąć: `sc stop` i `services.msc` dostają odmowę dostępu. Zostaje mu prawo zmiany uprawnień – to granica ochrony.
- **Token deinstalacji.** Panel → Huginn → agent → „Token deinstalacji”: rola administratora, powód i ponowne podanie hasła, wpis w audycie. Token jest jednorazowy, działa tylko na tym komputerze, domyślnie przez 24 h (do 7 dni). Panel pokazuje go raz; w bazie i na komputerze jest tylko skrót. Nowy token unieważnia poprzedni. Polecenie z tokenem samo pobiera świeżą konfigurację z panelu, więc token działa od razu. Użyty token panel oznacza na podstawie raportu agenta.
- **Wycofanie po deinstalacji (od 0.7.4).** Deinstalacja usuwa klucz prywatny agenta (`certs\agent.key`); konfiguracja i bufor zostają (`-purge` usuwa wszystko). Gdy agent zgłosi deinstalację tokenem wydanym w panelu dla tego komputera, panel unieważnia jego certyfikaty (rozsyłane do ingestu jak przy ręcznym unieważnieniu) i zapisuje `agent_retired` w audycie. Agent ma w Huginnie stan „wycofany” – znika z domyślnej listy (filtr „Wycofani”), historia zostaje. Ponowna instalacja na tym komputerze to nowa rejestracja tokenem i nowy identyfikator (identyfikatory nigdy nie są używane ponownie – zdarzenia z jednego identyfikatora zawsze pochodzą z jednego klucza).
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

## Logi IIS (od wersji 0.10)

Na serwerach WWW agent czyta też dzienniki IIS w formacie W3C (domyślny format IIS). Włączenie: opcja grupy *Logi IIS (serwery WWW)* w panelu (np. grupa „Serwery WWW”) albo w `agent.yaml`:

```yaml
iis:
  enabled: true
  log_dir: 'C:\inetpub\logs\LogFiles'   # domyślnie
```

- Każdy podkatalog `log_dir` z plikami `u_ex*.log` (witryna `W3SVC1`, `W3SVC2`…, także FTP) to osobny kanał agenta (`iis:W3SVC1`) – widoczny na stronie agenta w panelu. Nowa witryna jest wykrywana przy kolejnym uruchomieniu odczytu (zmiana konfiguracji grupy albo restart usługi).
- Pozycja jest zapisywana jak dla dzienników Windows: po przerwie agent wznawia od następnego wiersza. Nowy agent (bez zapisanej pozycji) zaczyna od bieżącego pliku dnia, bez historii.
- Pliki dzienne i godzinowe (`u_exRRMMDD.log`, `u_exRRMMDDGG.log`); agent przechodzi do nowszego pliku, gdy poprzedni nie zmienia się od 2 minut. Wymagane pola daty i czasu (`date`, `time` – domyślnie włączone); zalecane dodatkowo `cs-username`, `cs(User-Agent)`, `sc-status`, `sc-win32-status`.
- Na serwerze zdarzenia rozbiera wbudowany dekoder `iis` (zbiór `iis.access`): adres klienta w `source.ip`, użytkownik (uwierzytelnienie Windows/Basic) w `user.name`, wynik `failure` dla 401 i 403. Pola W3C zostają pod własnymi nazwami (`cs-method`, `cs-uri-query`, `sc-status`…), więc reguły Sigmy z `logsource: category: webserver` (albo `product: iis`) działają bez zmian.
- Agent czyta pliki jako SYSTEM; katalog domyślny IIS jest dla niego dostępny. Brak katalogu albo plików W3C – ostrzeżenie na stronie agenta.

## Agent Linux (od wersji 0.11)

Ten sam program `vardr-agent` w wersji dla Linuksa z systemd (amd64, arm64; Ubuntu, Debian, RHEL i pochodne, SUSE). Rdzeń jest wspólny z agentem Windows: rejestracja tokenem z panelu, wysyłka po mTLS, bufor dyskowy, heartbeat (Huginn), odnowienie certyfikatu i limity z grupy agentów.

```bash
# w folderze z vardr-agent, ca.crt (z serwera, certs/ca.crt) i tokenem z panelu (Bifröst)
sudo ./vardr-agent install -server 192.168.88.98 -token hdt_…
sudo vardr-agent status
```

- **Pliki:** program `/usr/local/sbin/vardr-agent`, konfiguracja i certyfikaty `/etc/vardr-agent` (tylko root, klucz `0600`), stan, bufor i log `/var/lib/vardr-agent`; usługa `vardr-agent.service` (start z systemem, restart po awarii, system plików tylko do odczytu poza tymi katalogami). Log usługi także w `journalctl -u vardr-agent`.
- **Polecenia** jak w Windows: `status`, `start`, `stop`, `restart`, `test`, `check`, `set-server`, `run` (konsola), `enroll` (rejestracja bez usługi), `./vardr-agent upgrade` (z folderu nowej wersji), `uninstall [-purge]` (klucz prywatny usuwany zawsze).
- **Źródło – dziennik systemd** (`journalctl -o json`, bez dodatkowych bibliotek): domyślnie wpisy uwierzytelniania (auth, authpriv – SSH, sudo, su, PAM, logind, zmiany kont i grup) oraz wszystkie o priorytecie *warning* i wyższym. Na serwer trafiają jako syslog RFC 5424 (źródło `syslog:journald`), więc działają wbudowany dekoder `linux` (`linux.auth`) i reguły Linuksa – tak samo jak dla serwerów wysyłających przez rsyslog. Dodatkowe jednostki albo programy w całości:

```yaml
journald:
  enabled: true
  units: [nginx.service]     # cała jednostka systemd
  identifiers: [cron]        # cały program (SYSLOG_IDENTIFIER)
  # all: true                # cały dziennik (duży wolumen)
```

- Pozycja odczytu to czas wpisu: po przerwie agent wznawia od niego, bez duplikatów (identyfikator zdarzenia z kursora dziennika). Nowy agent zaczyna od bieżących wpisów (`start_at: oldest` – od początku dziennika).
- **Źródło – Linux Audit (auditd)**: dziennik `/var/log/audit/audit.log` z rotacją. Rekordy jednego zdarzenia (SYSCALL, EXECVE, CWD, PATH… do EOE) trafiają na serwer razem (źródło `file:auditd`), rozbiera je wbudowany dekoder `linux-audit` (zbiór `linux.audit`, parser `audit`): uruchomione programy z argumentami (`process-start`, pola Sigmy `Image`, `CommandLine`), logowania i uwierzytelnienia, sudo, zmiany kont i grup, zmiany konfiguracji audytu, odmowy SELinux/AppArmor i zdarzenia reguł audytu (pole `key`). Konto `user` to konto logowania (AUID) – także po sudo. Domyślnie pomijane są typy powtarzane przy każdym zadaniu cron i sesji (CRED_*, USER_ACCT, USER_START, USER_END, LOGIN, SERVICE_*, BPF, NETFILTER_CFG); lista: `auditd.exclude`. Bez auditd agent czeka na plik (kanał bez błędu). Zalecane reguły audytu z kluczami `vardr_*` dla reguł detekcji (`rules/linux/linux_audit_*`):

```bash
sudo apt install auditd          # albo: sudo dnf install audit
vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules
sudo augenrules --load
```

```yaml
auditd:
  enabled: true                  # agent zainstalowany w 0.11.0 przed 1.8.1 – dopisz ręcznie
  # exclude: [CRED_ACQ, …]       # [] – bez pomijania
```

  Reguły Sigmy: `logsource: {product: linux, service: auditd}` albo `{product: linux, category: process_creation}`.
- **Limity z grupy:** priorytet jako waga CPU i I/O jednostki, limit CPU i twardy limit pamięci w cgroup usługi (`systemctl set-property --runtime`, zmiana bez restartu), miękki limit pamięci, EPS i przepustowość jak w Windows. Profil grupy (kanały Event Log) agenta Linux nie dotyczy.
- Bez roota (`vardr-agent run` jako zwykły użytkownik, np. w teście) agent czyta tylko to, co pokazuje mu `journalctl` – użytkownik w grupie `adm` albo `systemd-journal` widzi dziennik systemowy.
- **Ochrona** (włączana w grupie agentów, jak w Windows): agent zapisuje drop-in `/etc/systemd/system/vardr-agent.service.d/50-vardr-protect.conf` z `RefuseManualStop=yes` – `systemctl stop` i `restart` odmawiają. Zatrzymanie, aktualizacja i deinstalacja tylko z jednorazowym tokenem z panelu: `sudo vardr-agent stop -token …`, `sudo ./vardr-agent upgrade -token …`, `sudo vardr-agent uninstall -token …`; `sudo vardr-agent restart` działa bez tokenu (ponowne uruchomienie w procesie, SIGHUP). Do dziennika ochrony (alert w panelu) trafiają: polecenie bez ważnego tokenu, SIGTERM wysłany z pominięciem systemd (`kill`, `systemctl kill` – ignorowany, agent działa dalej), zabicie procesu (SIGKILL – systemd uruchamia agenta ponownie po 10 s, a ten zgłasza zabicie), zatrzymanie z pominięciem tokenu (np. `systemctl isolate`), zdjęcie drop-inu ochrony (przywracany), zmiana albo usunięcie pliku usługi (przywracany), wyłączenie startu z systemem (`systemctl disable` – włączany ponownie), maskowanie i obce drop-iny usługi (zgłaszane). Zamknięcie systemu nie jest alarmem. Root może ochronę obejść (np. zmieniając usługę i od razu ją zatrzymując) – celem jest utrudnić i wykryć, a przerwę w heartbeatach panel zgłasza i tak.
- **Źródło – pliki logów** (`files:`): dowolne pliki tekstowe, wiersz po wierszu, z rotacją przez zmianę nazwy (logrotate) i przez obcięcie (copytruncate). Wiersz trafia na serwer jako syslog z nazwą hosta agenta i nazwą programu `app` (źródło `syslog:file`, kanał `file:<ścieżka>`), więc rozbiera go dekoder dopasowany po `app` – ten sam, co dla wiadomości z rsyslog (kreator dekoderów w panelu); bez dekodera zdarzenie ma zbiór `syslog.generic`. Czas zdarzenia to chwila odczytu, chyba że dekoder bierze czas z treści. Wzorce (`*.log`) agent sprawdza co 30 s – nowy pasujący plik (np. log z datą w nazwie) czyta od razu od początku, bez restartu (od 0.12). Pierwsze uruchomienie czyta od końca pliku (`start_at: oldest` – od początku). Usługa ma własny `/tmp` (`PrivateTmp`) – pliki z `/tmp` nie są dla niej widoczne.

```yaml
files:
  - path: /var/log/nginx/*.log
    app: nginx
  - path: /opt/app/logs/app.log   # app domyślnie: nazwa pliku bez rozszerzenia
```

- **Paczka z panelu:** Bifröst przy tokenie wydaje `vardr-agent-<nazwa>-linux-<amd64|arm64>.tar.gz` – program, `ca.crt`, `server.txt`, `token.txt` (0600) i `install.sh`. Na serwerze: `tar xzf …`, `cd vardr-agent-<nazwa>/`, `sudo ./install.sh` (adres i token z plików obok). Programy dla obu architektur budowane są do `agent-dist/` (`deploy.sh agent`, `vardr-agent-linux-amd64`, `vardr-agent-linux-arm64`).
- **Automatyczne aktualizacje** (od 0.12) – jak w Windows, opis w [Automatyczne aktualizacje](#automatyczne-aktualizacje-od-wersji-010).

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
