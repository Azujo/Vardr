# Reguły detekcji

Reguły to pliki YAML w formacie [Sigma](https://sigmahq.io/docs/basics/rules.html) z rozszerzeniami Heimdalla (klucz `heimdall`). Leżą w repozytorium w `rules/` (`windows/`, `network/`, `cross/`) i są wdrażane na serwer. Jedna reguła działa w obu silnikach: **w locie** (każde zdarzenie z kolejki, alert w sekundy) i **zapytań** (ta sama reguła jako SQL na ClickHouse co minutę – nadrabia przerwy, spóźnione zdarzenia i limity pamięci). Kod: `internal/detect` (wczytanie, kompilacja, ocena, SQL), `server/internal/detector` (silniki, progi).

## Przykład

```yaml
title: Seria nieudanych logowań na jedno konto (brute force)
id: 2feca112-9567-41b7-83de-92c2516f6cdc
status: stable
description: |
  Co najmniej 10 nieudanych logowań (4625) na to samo konto w ciągu 5 minut.
author: Heimdall
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  computer_account:
    TargetUserName|endswith: '$'
  empty:
    TargetUserName: ['', '-']
  condition: selection and not computer_account and not empty
falsepositives:
  - Program z zapamiętanym starym hasłem
level: medium
heimdall:
  group_by: [TargetUserName]
  threshold:
    count: 10
    window: 5m
  suppress: 1h
  instructions: |
    {{count}} nieudanych logowań na konto {{TargetDomainName}}\{{TargetUserName}}
    w {{window}}. Sprawdź, skąd były próby …
```

## Pola nagłówka

| Pole | Wymagane | Znaczenie |
|---|---|---|
| `title` | tak | tytuł alertu |
| `id` | tak | stały identyfikator (UUID); zmiana `id` to nowa reguła (historia i ustawienia z panelu zostają przy starym) |
| `level` | tak | `informational`, `low`, `medium`, `high`, `critical` – poziom alertu i filtr kanałów powiadomień |
| `logsource` | tak | źródło (niżej) |
| `detection` | tak | selekcje i warunek |
| `status`, `description`, `author`, `references`, `tags`, `falsepositives`, `date`, `modified` | nie | opis w panelu; `tags` z ATT&CK (`attack.t1110`) |

## logsource

| `product` | `service` / `category` | Zdarzenia |
|---|---|---|
| `windows` | `security`, `system`, `application`, `sysmon`, `powershell`, `windefend`, `taskscheduler` | kanał dziennika Windows |
| `windows` | `category: process_creation` | Sysmon 1 albo Security 4688 |
| `windows` | `category: ps_script` | PowerShell 4104 |
| `windows` | `category: network_connection`, `file_event`, `dns_query`, `registry_set` | Sysmon 3, 11, 22, 13 |
| `fortigate` (`fortinet`) | – | `fortinet.fortigate` (dekoder syslog) |
| `mikrotik` (`routeros`) | – | `mikrotik.routeros` |
| `azure` (`entra`) | `signinlogs`, `auditlogs` | logi Entra ID z konektora |

Inne wartości są odrzucane przy wczytaniu. Reguła bez `service`/`category` obejmuje cały produkt (np. wszystkie zdarzenia Windows).

## detection

**Selekcja** to mapa `pole: wartość`. Wszystkie pola muszą pasować (I). Lista wartości oznacza dowolną z nich (LUB). Lista map oznacza dowolną z map. Lista słów (bez pól) oznacza słowa kluczowe szukane w treści zdarzenia (opis i oryginalny XML).

**Wartości:** tekst porównywany bez wielkości liter, `*` i `?` jako maski, liczby, `null` (pole nie istnieje albo puste).

**Modyfikatory** (`Pole|modyfikator`):

| Modyfikator | Znaczenie |
|---|---|
| (brak) | równe (z maskami `*`, `?`) |
| `contains`, `startswith`, `endswith` | zawiera, zaczyna się, kończy się |
| `re` | wyrażenie regularne RE2 (z wielkością liter, chyba że `(?i)`) |
| `cidr` | adres w sieci, np. `IpAddress|cidr: ['10.0.0.0/8', '192.168.0.0/16']` |
| `all` | z listą: wszystkie wartości muszą pasować (np. `CommandLine|contains|all: ['-enc', 'hidden']`) |
| `exists` | `true` – pole istnieje, `false` – nie istnieje |

**Warunek** (`condition`): nazwy selekcji z `and`, `or`, `not` i nawiasami oraz `1 of selection_*`, `all of selection_*`, `1 of them`, `all of them`. Jeden warunek tekstowy (bez listy warunków).

Nieobsługiwane i jawnie odrzucane (reguła nie działa „trochę”): agregacje Sigmy (`| count() by …`), `timeframe`, `near`, modyfikatory `base64offset`, `windash`, `wide` itp. Progi wyraża się przez `heimdall.threshold`.

## Pola zdarzenia

Reguła może używać trzech rodzajów nazw.

**Nazwy Sigmy i Windows:** `EventID`, `Channel`, `Provider_Name`, `Computer` oraz pola `EventData` (np. `TargetUserName`, `IpAddress`, `LogonType`, `CommandLine`, `Image`, `ScriptBlockText`). Część pól ma aliasy między źródłami, np. `Image` to też `NewProcessName` z 4688, a `SourceIp` to też `IpAddress` (lista: `internal/detect/event.go`, `aliases`).

**Nazwy wspólne (ECS):**

| Pole | Kolumna | Opis |
|---|---|---|
| `event.code` | `event_code` | Event ID |
| `event.dataset` | `event_dataset` | źródło, np. `windows.security` |
| `event.action`, `event.outcome` | `event_action`, `event_outcome` | akcja, wynik (`success`/`failure`) |
| `event.provider` | `event_provider` | dostawca |
| `host.name` | `host_name` | komputer albo urządzenie |
| `user.name`, `user.domain` | `user_name`, `user_domain` | konto |
| `user.identity` | `user_identity` | osoba (to samo konto w AD, Entra, na VPN) |
| `source.ip` | `source_ip` | adres źródłowy |
| `process.name`, `process.command_line` | | proces |
| `agent.id`, `message` | | agent, opis zdarzenia |

**Pola źródłowe** z dekoderów: dowolne klucze mapy `fields`, np. `fortinet.action`, `azure.app`, `source.geo.country_iso_code`. Zestaw pól danego źródła pokazuje Mímir (szczegóły zdarzenia).

Pole, którego nie ma w zdarzeniu, nie pasuje do żadnej wartości, z wyjątkiem `null` i `exists: false`.

## Rozszerzenia Heimdalla

```yaml
heimdall:
  mode: both            # stream | index_query | both (domyślnie both)
  group_by: [TargetUserName]
  suppress: 1h
  threshold:
    count: 10
    window: 5m
    distinct: TargetUserName   # opcjonalnie: liczba różnych wartości zamiast zdarzeń
  instructions: |
    …
  enabled: true
```

| Klucz | Znaczenie |
|---|---|
| `mode` | silnik: `stream` (tylko w locie), `index_query` (tylko zapytania – np. reguły kosztowne albo na danych spóźnionych), `both` |
| `group_by` | pola klucza alertu. Trafienia z tym samym kluczem w oknie `suppress` łączą się w jeden alert (rośnie licznik). Bez `group_by` każde zdarzenie to osobny alert. |
| `suppress` | okno łączenia, domyślnie 1h przy `group_by` |
| `threshold.count`, `window` | alert dopiero przy `count` (2–10 000) pasujących zdarzeniach z tym samym kluczem w dowolnym oknie `window` (10s–24h) liczonym po czasie zdarzenia. Do alertu trafiają wszystkie zdarzenia serii, potem kolejne aż do końca `suppress`. |
| `threshold.distinct` | zamiast liczby zdarzeń – liczba różnych wartości pola (np. password spraying: 5 różnych kont z jednego adresu). Ta sama próba widoczna w dwóch dziennikach nie zawyża wyniku. |
| `instructions` | co ma zrobić analityk; pokazywane w alercie i w powiadomieniu |
| `enabled` | `false` wyłącza regułę bez usuwania pliku (panel może to nadpisać) |

**Zmienne w `instructions`:** `{{Pole}}` – wartość pola z (pierwszego) zdarzenia, np. `{{TargetUserName}}`, `{{IpAddress}}`, `{{host.name}}`; brak wartości daje „(brak)”. Reguły progowe mają dodatkowo `{{count}}` (liczba zdarzeń albo wartości), `{{window}}` (okno) i `{{values}}` (lista wartości przy `distinct`).

## Reguły korelacyjne

Reguła korelacyjna łączy trafienia kilku reguł (albo wiele trafień jednej) w jeden alert. Format to [Sigma Correlation](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md). Reguły bazowe i korelacja mogą być w jednym pliku (dokumenty YAML oddzielone `---`) albo w osobnych plikach. Korelacja wskazuje reguły bazowe przez `id` albo `name`.

```yaml
title: Nowe konto od razu dodane do grupy uprzywilejowanej
id: fc22af54-b46e-449d-a6fd-e100cffa9153
level: critical
correlation:
  type: temporal_ordered
  rules:
    - 9f379649-a04b-43de-b3a0-25587cf713de # Utworzono konto (4720)
    - f406b909-37ba-4b21-b8c2-f4bd5cbf3192 # Dodano do grupy uprzywilejowanej
  group-by: [account]
  timespan: 1h
  aliases:
    account:
      9f379649-a04b-43de-b3a0-25587cf713de: TargetSid
      f406b909-37ba-4b21-b8c2-f4bd5cbf3192: MemberSid
  generate: true
heimdall:
  instructions: Konto {{key}} utworzono i dodano do grupy {{TargetUserName}} w {{window}}.
```

| Typ | Kiedy alert | `condition` |
|---|---|---|
| `event_count` | co najmniej N trafień reguł bazowych w oknie | `gte: N` (albo `gt: N-1`) |
| `value_count` | co najmniej N różnych wartości pola w oknie | `gte: N`, `field: <pole>` |
| `temporal` | wszystkie reguły bazowe trafiły w oknie, kolejność dowolna | – |
| `temporal_ordered` | wszystkie reguły bazowe trafiły w oknie, w kolejności z `rules` | – |

- **`group-by`** – zdarzenia łączone są tylko przy tych samych wartościach pól (np. to samo konto). Bez `group-by` liczą się wszystkie zdarzenia razem.
- **`aliases`** – gdy to samo „coś” ma w każdej regule bazowej inne pole (SID nowego konta to `TargetSid` w 4720, a `MemberSid` przy dodaniu do grupy). Alias jest nazwą w `group-by`, a pod nim reguła bazowa (`id` albo `name`) → pole.
- **`timespan`** – okno od `1m` do `24h` (jednostki `s`, `m`, `h`, `d`).
- **`generate`** – `false` (domyślnie): reguły bazowe same nie tworzą alertów (w panelu opis „Reguła bazowa korelacji”). `true`: reguły bazowe nadal alarmują, korelacja to dodatkowy alert o wyższym poziomie.
- **`heimdall`** – w regule korelacyjnej tylko `enabled`, `suppress` (domyślnie większe z 1 h i `timespan`) i `instructions`. W instrukcji oprócz pól ostatniego zdarzenia są `{{count}}` (liczba zdarzeń), `{{window}}`, `{{rules}}` (tytuły reguł, które trafiły) i `{{key}}` (wartości `group-by`).

**Jak działa.** Detektor co minutę (razem z korelacjami wbudowanymi) szuka w `siem.events` kluczy z nowo przyjętych zdarzeń reguł bazowych. Dla tych kluczy pobiera zdarzenia z okna `timespan` wstecz (plus godzina na zdarzenia spóźnione) i sprawdza warunek. Alert dostaje silnik `correlation` i zawiera wszystkie zdarzenia, które spełniły korelację. Ponowne przebiegi nie dublują zdarzeń (para reguła–zdarzenie jest w alercie raz), a kolejne trafienia tego samego klucza w oknie `suppress` dołączają do otwartego alertu.

**Ograniczenia.** Bez warunków `lt`, `lte`, `eq`, `neq` (alert na „za mało” zdarzeń nie ma sensu przy ocenie nowych zdarzeń) i bez typu `value_sum`/`value_avg`. Reguła bazowa nie może być progowa (`heimdall.threshold`) – próg wyraża sama korelacja. Najwięcej 50 000 zdarzeń jednej korelacji w przebiegu; ponad limit przebieg kończy się błędem w dzienniku detektora – zawęź reguły bazowe albo skróć okno. Korelacje wbudowane („udane po nieudanych”, „nowy kraj”) zostają w kodzie, bo wymagają historii spoza okna.

### Kreator korelacji w panelu

*Reguły detekcji → Nowa korelacja (kreator)* (rola `analyst`; zapis – `admin`) składa regułę korelacyjną z przykładowych zdarzeń:

1. **Zdarzenia.** Do 10 przykładów – z wyszukiwarki w kreatorze albo z Mímira (szczegóły zdarzenia → „Dodaj do kreatora korelacji”). Lista żyje w tej karcie przeglądarki.
2. **Kroki.** Dla każdego zdarzenia kreator pokazuje wdrożone reguły, które do niego pasują (reguły progowe nie mogą być bazą), albo proponuje nową regułę bazową z zaznaczonych pól (domyślnie rodzaj zdarzenia: `EventID`, a dla urządzeń `event.action` i `event.outcome`). Zdarzenia z tym samym wyborem to jeden krok; kolejność kroków – według czasu przykładów.
3. **Warunek.** Klucz to wartość, która występuje we wszystkich krokach (np. SID nowego konta jako `TargetSid` w 4720 i `MemberSid` w 4728 – kreator sam dopisze `aliases`). Jeden krok: wartość wspólna wszystkim przykładom, a do `value_count` pole, którego wartości się różnią. Typ i okno są podpowiadane (okno ≈ dwukrotność odstępu między przykładami).
4. **Opis i test.** Tytuł, poziom, opis, instrukcja, `generate` (gdy korelacja używa wdrożonych reguł, kreator domyślnie zostawia ich alerty). Wygenerowany YAML można poprawić ręcznie i przetestować na historii jak każdą regułę.

**Reguły z panelu** są zapisywane w Sadze (`gjallarhorn.panel_rules`), a detektor wczytuje je obok katalogu `rules/` jako plik `panel/<id korelacji>.yml` (w ciągu 30 s, bez wdrożenia). Mają historię wersji, włączanie i wyłączanie jak reguły z plików; administrator może je edytować (YAML) i usuwać (powód i hasło, audyt). Id reguł z panelu nie może powtarzać id reguł wdrożonych – przy konflikcie wygrywa plik z repozytorium. Dobrą regułę warto potem przenieść do repozytorium (`rules/correlation/`) i usunąć z panelu.

## Dobre praktyki

- **Grupuj po tym, co analityk zablokuje albo sprawdzi:** konto (brute force), adres (spraying), osoba (`user.identity` – próby z wielu źródeł), komputer (podejrzane procesy).
- **Wykluczenia jako osobne selekcje** (`computer_account`, `empty`, `local`) w warunku `and not …`, z opisem w `falsepositives`.
- **Instrukcja konkretna:** co sprawdzić, czym odróżnić fałszywy alarm, co zrobić przy prawdziwym incydencie.
- **Poziom wg skutku:** `critical` tylko dla zdarzeń niemal pewnych (np. wyczyszczony dziennik Security), `high` – wymaga reakcji w godzinach, `medium` – do przejrzenia, `low` – kontekst.
- **Reguła na wielu źródłach** (np. logowania w AD, Entra i na VPN) używa pól wspólnych (`event.outcome`, `user.identity`, `source.ip`) i warunku po `event.dataset`. Przykład: `rules/cross/password_spraying_multi_source.yml`.
- **Nie zmieniaj `id`** przy poprawkach – historia wersji i ustawienia z panelu są przypisane do `id`.

## Testowanie

1. **Lokalnie:** `go run ./server/cmd/siem-detector check rules` wczytuje wszystkie reguły i wypisuje błędy (kod wyjścia 1).
2. **W panelu** (*Reguły detekcji → Test reguły*, rola `analyst`): wklejona reguła jest uruchamiana na zdarzeniach z ClickHouse z ostatnich 1–168 godzin. Widać trafienia, a dla reguł progowych – alerty, które by powstały. Regułę korelacyjną testuje się tak samo: wklejony tekst może zawierać też reguły bazowe (dokumenty po `---`), a brakujące są brane z wczytanych reguł; wynik to alerty z kluczem i zdarzeniami. Test korzysta z tych samych limitów co wyszukiwarka.
3. **Test zgodności silników** (`server/internal/detector/compat_test.go`): korpus zdarzeń (`testdata/`) przechodzi przez oba silniki, a test sprawdza, że każda reguła z `rules/` daje te same trafienia w locie i w SQL. Nowa reguła powinna mieć zdarzenie w korpusie, które ją wywołuje. Uruchomienie: [rozwoj.md](rozwoj.md#testy).
4. **W laboratorium:** wywołanie zdarzenia na prawdziwym źródle (np. nieudane logowania do DC, `fortisim -scenario vpn-brute`, `curl … entrasim/sim/scenario?name=spray`) i sprawdzenie alertu w Gjallarhornie.

## Wdrażanie

```bash
deploy/lab/deploy.sh rules
```

Skrypt najpierw sprawdza reguły (`siem-detector check`). Potem kopiuje je na VM do nowego katalogu `rules/v<czas>` i atomowo przełącza dowiązanie `rules/current`. Detektor wczytuje zmiany w ciągu 30 s bez restartu. Reguła z błędem nie zatrzymuje pozostałych: jest pomijana, a błąd widać w panelu i w alercie Grafany „Reguły detekcji z błędami”. Każda zmiana treści reguły to nowa wersja w historii (panel → reguła → Wersje).

**Włączanie i wyłączanie w panelu** (administrator, z powodem i hasłem) nadpisuje `enabled` z pliku i trafia do audytu. „Przywróć z pliku” cofa nadpisanie.

## Reguły wbudowane

Nie są plikami Sigmy – działają w kodzie detektora, ale są widoczne w panelu jak reguły (plik „(wbudowana)”):

| Reguła | Id | Co wykrywa | Wyłączana w panelu |
|---|---|---|---|
| Utrata łączności z agentem | `heimdall-agent-heartbeat-lost` | brak heartbeatu ponad próg grupy agentów; zamyka się sama po powrocie | nie (próg w grupie) |
| Próba sabotażu agenta | `heimdall-agent-tamper` | zatrzymanie bez tokenu, zmiana uprawnień usługi, zabicie procesu, fałszywy token, brak powrotu po aktualizacji | nie (ochrona w grupie) |
| Udane logowanie po serii nieudanych | `heimdall-success-after-failures` | ≥5 nieudanych logowań osoby w 30 min (dowolne źródła), potem udane; kolejne udane logowania przy otwartym alercie podbijają licznik | tak |
| Logowanie z nowego kraju | `heimdall-signin-new-country` | udane logowanie z kraju spoza historii osoby z 30 dni (Entra ID) | tak |
| Cisza źródła zdarzeń | `heimdall-source-silent` | urządzenie syslog albo chmura milczy dłużej niż najdłuższa przerwa z 7 dni + 1 h | tak |

Kod: `server/internal/detector/heartbeat.go`, `tamper.go`, `correlate.go`, `silence.go`. Korelacje i cisza źródła czytają ClickHouse (`siem.auth_events`, `siem.events`), więc wymagają `SIEM_DETECTOR_CH_PASSWORD`.

## Reguły w repozytorium

| Plik | Co wykrywa |
|---|---|
| `windows/security_brute_force_logon.yml` | ≥10 nieudanych logowań (4625) na konto w 5 min |
| `windows/security_brute_force_kerberos.yml` | seria błędnych haseł Kerberos (4771) |
| `windows/security_password_spraying.yml` | ≥5 różnych kont z jednego adresu w 10 min |
| `windows/security_log_cleared.yml`, `system_eventlog_cleared.yml` | wyczyszczony dziennik (1102, 104) |
| `windows/security_user_created.yml` | utworzenie konta (4720) |
| `windows/security_privileged_group_member_added.yml` | dodanie do grupy uprzywilejowanej |
| `windows/system_service_install_suspicious.yml` | instalacja usługi z podejrzaną ścieżką (7045) |
| `windows/system_security_service_stopped.yml` | zatrzymanie Sysmona |
| `windows/proc_powershell_encoded_command.yml` | PowerShell z zakodowanym poleceniem |
| `windows/ps_script_suspicious_keywords.yml` | podejrzane słowa w skryptach PowerShell (4104) |
| `network/fortigate_vpn_brute_force.yml`, `fortigate_admin_login_failures.yml` | seria nieudanych logowań do VPN i panelu FortiGate |
| `network/mikrotik_login_brute_force.yml` | seria nieudanych logowań do routera MikroTik |
| `cross/password_spraying_multi_source.yml` | spraying z jednego adresu łącznie w AD, Entra, VPN i na routerze |
| `correlation/new_account_privileged.yml` | korelacja: konto utworzone i w ciągu godziny dodane do grupy uprzywilejowanej |
| `correlation/account_failures_many_sources.yml` | korelacja: nieudane logowania na jedno konto z ≥4 adresów w 15 min (z regułą bazową) |
