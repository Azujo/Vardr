# Dekodery

Dekoder zamienia wiadomość spoza Windows na zdarzenie znormalizowane. Obsługuje dwa rodzaje wiadomości: syslog z kolektora (zapory, routery) oraz rekordy JSON z konektora API (Entra ID). Dekodery to pliki YAML:

- **wbudowane** w program normalizatora (`internal/decode/builtin/`: `fortigate`, `mikrotik`, `entra-signin`, `entra-audit`);
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

## Nowe urządzenie – krok po kroku

1. **Logi.** Ustaw na urządzeniu syslog na adres kolektora (UDP/TCP 514). Dopisz sieć urządzenia do `syslog.allow` kolektora.
2. **Próbki.** Wiadomości bez dekodera pojawią się w Mímirze jako `dataset:syslog.generic`. Skopiuj kilka różnych.
3. **Nowy dekoder.** W panelu (*Dekodery → Nowy dekoder*) wpisz `match`, który wybiera tylko to urządzenie (np. `host`, `peer` albo charakterystyczny fragment treści), i parser.
4. **Test.** Przetestuj na próbkach i na nierozpoznanych wiadomościach, uzupełnij `fields`, `outcome` i `time`. Zapisz z powodem.
5. **Sprawdzenie.** Nowe wiadomości mają `dataset` dekodera. Wpisy z kwarantanny (jeśli były) przetwórz ponownie.
6. **Reguły.** Reguła dla nowego źródła potrzebuje `logsource.product`. Nowy produkt to jeden wpis w `internal/detect/compile.go` (`products`: nazwa produktu → `event.dataset`) i nowa wersja detektora.

Dekoder sprawdzony na stałe warto przenieść do `internal/decode/builtin/` (z próbkami w teście), żeby był w każdej instalacji.
