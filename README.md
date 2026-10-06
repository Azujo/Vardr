# SIEM – własny system SIEM

Projekt według roadmapy `Roadmap_wlasnego_SIEM_v1.2.md` (wersja 1.2.2).
Obecny stan: **etap 1 – agent Windows i testowy endpoint przyjmujący**.

## Struktura

```
cmd/
  siem-agent/          agent Windows (konsola + usługa Windows)
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
bin\siem-agent.exe -config configs\agent.lab.yaml check
bin\siem-agent.exe -config configs\agent.lab.yaml run
```

Zdarzenia trafiają do `data\events.ndjson`, stan agenta do `data\agent\state.json`.

## Usługa Windows (wymaga administratora)

```powershell
bin\siem-agent.exe -config C:\ProgramData\SiemAgent\agent.yaml install
bin\siem-agent.exe start
bin\siem-agent.exe status
bin\siem-agent.exe stop
bin\siem-agent.exe uninstall
```

Usługa działa jako LocalSystem (dostęp do kanału Security), startuje automatycznie
i jest restartowana po awarii (5 s / 30 s / 60 s). Log: `<state_dir>\agent.log`.

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
bin\siem-agent.exe -config C:\ProgramData\SiemAgent\agent.yaml status
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
i Administratorzy. `siem-agent check` pokazuje, czy klucz i katalog stanu są
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
- właściwy serwer: NATS JetStream → normalizator → ClickHouse (etap 1, część serwerowa)
