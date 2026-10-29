# Dekodery

Dekoder zamienia wiadomość spoza Windows na zdarzenie znormalizowane. Obsługuje dwa rodzaje wiadomości: syslog z kolektora (zapory, routery) oraz rekordy JSON z konektora API (Entra ID). Dekodery to pliki YAML:

- **wbudowane** w program normalizatora (`internal/decode/builtin/`: `fortigate`, `mikrotik`, `linux`, `pfsense`, `cisco-asa`, `entra-signin`, `entra-audit`; konfiguracja urządzeń – [Źródła z dekoderem wbudowanym](#źródła-z-dekoderem-wbudowanym));
- **z panelu** (*Dekodery*, administrator), trzymane w Sadze z historią wersji i dostarczane normalizatorom przez NATS KV `SIEM_DECODERS` w ciągu kilku sekund, bez restartu.

Dekoder z panelu o tym samym `id` co wbudowany go zastępuje. „Przywróć wersję wbudowaną” cofa tę zmianę. Kod: `internal/decode`.

## Jak normalizator wybiera dekoder

1. **Nagłówek.** Wiadomość syslog jest rozbierana na nagłówek (RFC 3164, RFC 5424 albo sam `<PRI>`): priorytet, czas, host, program, PID i treść. Rekord API nie ma nagłówka – programem jest źródło konektora (`entra:signin`, `entra:audit`).
2. **Wybór.** Dekodery są sprawdzane od najwyższego `priority`. Wygrywa pierwszy, którego warunki `match` pasują.
3. **Brak dekodera.** Wiadomość syslog bez pasującego dekodera trafia do ClickHouse jako zbiór `syslog.generic` (sama treść i nagłówek). Rekord API bez dekodera trafia do kwarantanny.
4. **Parser.** Dekoder rozbiera treść parserem; jeśli treść do parsera nie pasuje (np. niepoprawny JSON), zdarzenie trafia do kwarantanny z powodem. Po poprawie dekodera można je przetworzyć ponownie (panel → Kwarantanna).

Każde zdarzenie dostaje w `fields` pola nagłówka (`syslog.peer` – adres nadawcy, `syslog.app`, `syslog.severity`, `syslog.facility`, `syslog.format`) oraz `decoder.id` i `decoder.version`. Czas z nagłówka bez strefy jest liczony w strefie `SIEM_SYSLOG_TZ` (domyślnie Europe/Warsaw).

## Format

```yaml
id: mikrotik                      # 2–64 znaki: małe litery, cyfry, . _ -
title: MikroTik RouterOS – logowania, DHCP, zapora
description: |
  …
version: 2                        # zwiększaj przy każdej zmianie (widoczne w zdarzeniu)
priority: 50                      # wyższy sprawdzany wcześniej
dataset: mikrotik.routeros        # event.dataset zdarzeń; windows.* i syslog.generic są zarezerwowane
match: …
parser: …
fields: …                         # mapowanie na pola wspólne
set: …                            # stałe wartości pól
outcome: …                        # event.outcome z wartości pola
time: …                           # czas zdarzenia z treści
samples: […]                      # przykładowe wiadomości – test dekodera
```

### match – kiedy dekoder pasuje

Wszystkie podane warunki muszą być spełnione (I):

| Warunek | Znaczenie |
|---|---|
| `peer: [192.168.88.1/32, 10.0.0.0/8]` | adres nadawcy w jednej z sieci |
| `host: [MikroTik]` | nazwa hosta z nagłówka (bez wielkości liter) |
| `app: [sshd]` | nazwa programu z nagłówka (dla API: źródło, np. `entra:signin`) |
| `app_regex: '^(system\|firewall)(,.*)?$'` | wyrażenie RE2 na nazwie programu |
| `contains: ['logid=', 'devname=']` | treść zawiera wszystkie fragmenty |
| `regex: '…'` | wyrażenie RE2 na treści |
| `any: [ {…}, {…} ]` | dowolna z alternatyw (każda to zestaw warunków jak wyżej, bez zagnieżdżonego `any`) |

Warunki powinny być na tyle wąskie, żeby dekoder nie przechwytywał cudzych wiadomości. Panel pokazuje przesłonięcia: test na ostatnich nierozpoznanych wiadomościach z pełnym zestawem dekoderów.

### parser – rozbiór treści

| `type` | Działanie | Opcje |
|---|---|---|
| `kv` | pary `klucz=wartość` (wartości w cudzysłowach mogą mieć spacje) – FortiGate | – |
| `json` | obiekt JSON; zagnieżdżone pola jako `a.b.c`, tablice z indeksem (`targetResources.0.userPrincipalName`) | – |
| `csv` | kolumny rozdzielone separatorem | `separator` (jeden znak), `columns: [..]` |
| `regex` | pierwszy pasujący wzorzec; grupy nazwane `(?P<nazwa>…)` to pola | `patterns: [{regex, set}]` – `set` to stałe pola dla danego wzorca (np. `event.action: login`) |
| `audit` | zdarzenie Linux Audit (auditd): rekordy `type=… msg=audit(…)` jednego zdarzenia; pola rekordów, tłumaczenia formatu ENRICHED (wielkie litery) i pola znormalizowane: `action`, `outcome`, `user`, `target_user`, `cmdline`, `file.path`, `src_ip`, `dest_ip`, `key`, `audit.ms` (czas) – dekoder `linux-audit` | – |
| `none` | bez rozbioru (sama treść w `message`) | – |

Wszystkie pola z parsera trafiają do `fields` pod swoimi nazwami (poza zarezerwowanymi nazwami nagłówka i dekodera). W regułach i w Mímirze są dostępne jako `fields.nazwa`.

### fields – mapowanie na pola wspólne

```yaml
fields:
  host.name: devname
  user.name: [user, srcuser, dstuser]     # pierwsze niepuste z listy
  source.ip: [srcip, remip]
  event.action: action
  event.code: logid
  message: [msg, logdesc]
```

Cele: `host.name`, `user.name`, `user.domain`, `source.ip`, `event.action`, `event.code` (liczba), `event.provider`, `process.name`, `message` oraz dowolne pola dodatkowe (np. `source.geo.country_iso_code`, `azure.app`), które trafiają do `fields`. Z `user.name` normalizator wyznacza osobę (`user.identity`).

### set, outcome, time

```yaml
set:                       # stałe wartości (np. dla całego dekodera)
  event.action: sign-in

outcome:                   # event.outcome z pierwszego niepustego pola
  field: [status, action]
  failure: [failed, deny, ssl-login-fail]
  success: [success, accept, ssl-login]
  otherwise: failure       # opcjonalnie: wynik dla wartości spoza list (np. kod błędu ≠ 0)

time:                      # czas zdarzenia z treści (dokładniejszy niż nagłówek)
  fields: [date, time, tz]                   # łączone spacją
  layout: "2006-01-02 15:04:05 -0700"        # układ Go albo unix | unix_ms | unix_ns | rfc3339
  timezone: Europe/Warsaw                    # gdy czas bez strefy
```

`event.outcome` jest kluczowe dla korelacji i reguł logowania: `failure` i `success` muszą być ustawione dla logowań, żeby zdarzenie trafiło do tabeli logowań (`siem.auth_events`) i do reguł „udane po nieudanych”. Warunki logowań dla nowych źródeł dopisuje się w `server/internal/detector/correlate.go` i `deploy/lab/clickhouse/init/03-auth-events.sh` (test pilnuje zgodności).

### samples – próbki

Próbki to prawdziwe wiadomości (z nagłówkiem syslog). Przy zapisie w panelu każda próbka musi pasować do `match` i dać się rozebrać parserem – dekoder z niepasującą próbką nie zostanie zapisany. Próbki wbudowanych dekoderów sprawdzają testy (`internal/decode`).

## Kreator dekoderów

Dekoder dla nowego urządzenia można złożyć bez pisania YAML-a i wyrażeń regularnych: **Dekodery → Kreator z próbek** (nierozpoznane wiadomości z ostatnich 7 dni albo wklejone) albo **Kwarantanna → kreator dekodera** przy grupie wiadomości syslog.

1. **Próbki.** Kreator rozbiera nagłówki syslog i rozpoznaje rodzaj treści: tekst, pary `klucz=wartość` albo JSON (można to zmienić).
2. **Oznaczanie pól.**
   - *Tekst:* zaznacz myszą fragment wiadomości i kliknij etykietę albo przeciągnij ją na zaznaczenie. Etykiety: czas, użytkownik, domena, adres źródłowy i docelowy, port, komputer, akcja, wynik, kod, program, treść, własne pole, **dowolne** (fragment zmienny, bez zapisu – np. protokół) i **rozpoznawanie** (stały fragment, po którym dekoder pozna te wiadomości). Każdy rodzaj wiadomości (np. logowanie udane i nieudane) oznacza się osobno – powstają osobne wzorce, każdy z własną akcją i wynikiem.
   - *klucz=wartość i JSON:* etykieta przy każdym polu; „wymagaj” – warunek rozpoznawania.
3. **Ustawienia.** Id, nazwa, zbiór danych, priorytet, warunki rozpoznawania (program, host, nadawca z nagłówka), format czasu (rozpoznawany z przykładu, także czas złożony z kilku pól) i wartości wyniku (udane/nieudane).
4. **Sprawdzenie.** Definicja jest testowana na wszystkich próbkach w trakcie oznaczania: ✓ rozpoznana z polami, ✗ nie (kliknięcie otwiera ją do oznaczenia jako kolejny wzorzec), ↷ obsługuje ją inny dekoder.
5. **Zapis.** „Zapisz i wdroż” (administrator) albo „Otwórz w edytorze”, żeby dopracować YAML ręcznie.

Kreator buduje wzorzec z tekstu wokół zaznaczeń: odstępy i liczby są uogólniane, długie odcinki zastępowane kotwicą z ostatnich słów przed polem. Słowo, które w wiadomościach tego rodzaju się zmienia, a nie jest polem, oznacz jako „dowolne” – inaczej wzorzec obejmie tylko wiadomości z tym samym słowem (widać to w sprawdzeniu).

## Źródła z dekoderem wbudowanym

Wszystkie wysyłają syslog na adres kolektora (UDP albo TCP 514); sieć urządzenia musi być w `syslog.allow` kolektora. Reguły dla tych źródeł: [reguly.md](reguly.md#reguły-w-repozytorium).

| Źródło | Dekoder | `event.dataset` | `product` w regułach |
|---|---|---|---|
| FortiGate | `fortigate` | `fortinet.fortigate` | `fortigate` |
| MikroTik RouterOS | `mikrotik` | `mikrotik.routeros` | `mikrotik` |
| Serwery Linux (rsyslog) | `linux` | `linux.auth` | `linux` |
| pfSense, OPNsense | `pfsense` | `pfsense.firewall` | `pfsense` (`opnsense`) |
| Cisco ASA, Firepower (FTD) | `cisco-asa` | `cisco.asa` | `cisco` (`asa`) |
| IIS (pliki W3C, agent Windows – nie syslog) | `iis` | `iis.access` | `iis`, `category: webserver` – zob. [agent.md](agent.md#logi-iis-od-wersji-010) |

Logowania z tych źródeł (pola `event.action: login` i `event.outcome`, w Cisco ASA także `vpn-connect`) trafiają do tabeli logowań i do korelacji „udane po nieudanych” razem z AD, Entra ID i VPN.

### Linux przez rsyslog

Dekoder rozpoznaje programy `sshd` (także `sshd-session` z OpenSSH 9.8+), `sudo`, `su`, `useradd`, `userdel`, `usermod`, `groupadd`, `gpasswd`, `passwd`, `chpasswd` i `systemd-logind`: logowania SSH (z polem `invalid_user` dla nieistniejących kont), polecenia i odmowy sudo (`process.command_line`, `target_user`, `sudo_error`), su, nieudane uwierzytelnienia PAM, sesje oraz zmiany kont i grup (`target_user`, `group`). Na serwerze – plik `/etc/rsyslog.d/90-vardr.conf`:

```
# auth i authpriv do kolektora Vardr; kolejka na dysku przy przerwie w łączności
auth,authpriv.* action(type="omfwd" target="kolektor.firma.pl" port="514" protocol="tcp"
                       template="RSYSLOG_SyslogProtocol23Format"
                       queue.type="LinkedList" queue.filename="vardr" queue.maxDiskSpace="100m"
                       queue.saveOnShutdown="on" action.resumeRetryCount="-1")
```

Szablon `RSYSLOG_SyslogProtocol23Format` (RFC 5424) przesyła czas ze strefą – domyślny format RFC 3164 jej nie ma i czas liczy się w strefie `SIEM_SYSLOG_TZ` (serwer w UTC dałby przesunięcie). Potem `sudo systemctl restart rsyslog`. System bez rsyslog (sam journald, np. minimalny Debian) – zainstaluj pakiet `rsyslog`; czyta dziennik systemd. Sprawdzenie: `logger -p authpriv.notice "test vardr"` – wiadomość widać w Mímirze (`host.name` serwera).

### Syslog przez TLS

Zwykły syslog idzie otwartym tekstem i bez uwierzytelnienia – w sieci, której nie kontrolujesz (oddział przez internet, sieć współdzielona), lepiej wysyłać go przez TLS (RFC 5425, port 6514). Kolektor przyjmuje TLS obok UDP/TCP; urządzenia, które to potrafią (rsyslog, syslog-ng, FortiGate z `mode reliable` i `enc-algorithm`), przechodzą na nowy port, reszta zostaje przy 514.

1. Certyfikat kolektora (samopodpisany, 10 lat; nazwa i adres, pod którymi urządzenia łączą się z serwerem):
   ```bash
   cd /opt/vardr
   sudo docker compose run --rm collector tls-cert -dir /collector -host kolektor.firma.pl,10.0.0.5
   ```
   Można też użyć certyfikatu z firmowego CA – wtedy wskaż go w `tls_cert`/`tls_key`.
2. W `collector/collector.yaml`, w sekcji `syslog`:
   ```yaml
   tls: ":6514"
   tls_cert: certs/syslog.crt
   tls_key: certs/syslog.key
   ```
   i `sudo docker compose restart collector`. Port 6514 jest wystawiony w `docker-compose.yml`; na zaporze otwórz go tylko dla sieci urządzeń.
3. Na urządzeniu wskaż `collector/certs/syslog.crt` jako zaufane CA. rsyslog (pakiet `rsyslog-gnutls`):
   ```
   global(DefaultNetstreamDriverCAFile="/etc/rsyslog.d/vardr-ca.crt")
   auth,authpriv.* action(type="omfwd" target="kolektor.firma.pl" port="6514" protocol="tcp"
                          StreamDriver="gtls" StreamDriverMode="1"
                          StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="kolektor.firma.pl"
                          template="RSYSLOG_SyslogProtocol23Format"
                          queue.type="LinkedList" queue.filename="vardr" queue.maxDiskSpace="100m"
                          queue.saveOnShutdown="on" action.resumeRetryCount="-1")
   ```

**Certyfikat urządzenia (opcjonalnie).** Samo TLS szyfruje i potwierdza urządzeniu tożsamość kolektora, ale nadal każdy z sieci z listy `allow` może coś wysłać. Gdy urządzenia mają certyfikaty z firmowego CA, dodaj `tls_client_ca: certs/devices-ca.crt` (kolektor odrzuci połączenie bez ważnego certyfikatu z tego CA) i ewentualnie `tls_client_names: ["fw1.firma.pl", "srv-www"]` (dozwolone CN lub nazwy DNS z certyfikatu). W rsyslog: `DefaultNetstreamDriverCertFile` i `DefaultNetstreamDriverKeyFile` w `global(...)`. Odrzucone połączenia liczy `tls_failed` w logu kolektora (`syslog: liczniki`).

Wiadomości z TLS mają w Mímirze źródło `syslog:tls`; dekodery działają tak samo jak dla UDP/TCP.

### pfSense i OPNsense

- **pfSense:** *Status → System Logs → Settings*: *Enable Remote Logging*, serwer `kolektor:514`, zawartość *Firewall Events* i *System Events* (logowania do panelu). Zablokowany ruch jest logowany przez domyślną regułę blokującą (*Log packets matched from the default block rules*); własne reguły – opcja *Log*.
- **OPNsense:** *System → Settings → Logging → Remote*: nowy cel (UDP albo TCP, port 514), aplikacje `filter` (filterlog) i `audit` (logowania do panelu); reguły zapory z opcją *Log*.

Dekoder rozpoznaje wpisy `filterlog` (IPv4 i IPv6: `fw_action` – pass/block/reject, `interface`, `direction`, `proto`, adresy i porty, `dst_port`) oraz udane i nieudane logowania do panelu WWW. Logowania SSH do zapory rozpoznaje dekoder `linux`.

### Cisco ASA i Firepower

```
logging enable
logging timestamp
logging trap informational
logging host inside 10.0.0.20
```

(`10.0.0.20` – kolektor, `inside` – interfejs, za którym jest.) `logging timestamp` daje dokładny czas zdarzenia; bez niego liczy się czas przyjęcia. Przy syslog przez TCP (`logging host inside 10.0.0.20 tcp/514`) ASA domyślnie wstrzymuje ruch, gdy serwer syslog jest niedostępny – dodaj `logging permit-hostdown` albo zostań przy UDP. Firepower (FTD): ustawienia syslog w *Platform Settings* w FMC.

Dekoder ustawia `event.code` na numer komunikatu i rozpoznaje: odrzucony i dozwolony ruch list dostępu (106023, 106100, 106001/106006/106007/106015), logowania administratorów (605004/605005, 611101/611102), uwierzytelnienia AAA i VPN (113004, 113005, 113015), sesje AnyConnect (113039 – `vpn-connect`, 722051, 113019) i polecenia administratorów (111008, 111010). Pozostałe komunikaty – `event.action: other` z treścią.

## Nowe urządzenie – krok po kroku

1. **Logi.** Ustaw na urządzeniu syslog na adres kolektora (UDP/TCP 514). Dopisz sieć urządzenia do `syslog.allow` kolektora.
2. **Próbki.** Wiadomości bez dekodera pojawią się w Mímirze jako `dataset:syslog.generic`. Skopiuj kilka różnych.
3. **Nowy dekoder.** W panelu (*Dekodery → Nowy dekoder*) wpisz `match`, który wybiera tylko to urządzenie (np. `host`, `peer` albo charakterystyczny fragment treści), i parser.
4. **Test.** Przetestuj na próbkach i na nierozpoznanych wiadomościach, uzupełnij `fields`, `outcome` i `time`. Zapisz z powodem.
5. **Sprawdzenie.** Nowe wiadomości mają `dataset` dekodera. Wpisy z kwarantanny (jeśli były) przetwórz ponownie.
6. **Reguły.** Reguła dla nowego źródła potrzebuje `logsource.product`. Nowy produkt to jeden wpis w `internal/detect/compile.go` (`products`: nazwa produktu → `event.dataset`) i nowa wersja detektora.

Dekoder sprawdzony na stałe warto przenieść do `internal/decode/builtin/` (z próbkami w teście), żeby był w każdej instalacji.
