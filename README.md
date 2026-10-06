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
- właściwy serwer: NATS JetStream → normalizator → ClickHouse (etap 1, część serwerowa)
