# Reguły detekcji

Reguły to pliki YAML w formacie [Sigma](https://sigmahq.io/docs/basics/rules.html) z rozszerzeniami Vardra (klucz `vardr`). Leżą w repozytorium w `rules/` (`windows/`, `network/`, `cross/`) i są wdrażane na serwer. Jedna reguła działa w obu silnikach: **w locie** (każde zdarzenie z kolejki, alert w sekundy) i **zapytań** (ta sama reguła jako SQL na ClickHouse co minutę – nadrabia przerwy, spóźnione zdarzenia i limity pamięci). Kod: `internal/detect` (wczytanie, kompilacja, ocena, SQL), `server/internal/detector` (silniki, progi).

## Przykład

```yaml
title: Seria nieudanych logowań na jedno konto (brute force)
id: 2feca112-9567-41b7-83de-92c2516f6cdc
status: stable
description: |
  Co najmniej 10 nieudanych logowań (4625) na to samo konto w ciągu 5 minut.
author: Vardr
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
vardr:
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
| `status`, `description`, `author`, `references`, `tags`, `falsepositives`, `date`, `modified` | nie | opis w panelu; `tags` z ATT&CK – niżej |

### Tagi MITRE ATT&CK

Tagi w konwencji Sigmy: technika `attack.t1110.001`, taktyka `attack.credential_access`; grupy i oprogramowanie (`attack.g0016`, `attack.s0002`) są dozwolone, ale nie trafiają do macierzy. Każda reguła, która tworzy alerty, powinna mieć co najmniej jedną technikę (reguła bazowa korelacji – nie musi; technikę ma korelacja).

- **Słownik**: ATT&CK Enterprise wbudowany w Vardra (`internal/attack/enterprise.json`, obecnie wersja 20). Od wersji 20 taktyka Defense Evasion jest podzielona na `stealth` i `defense_impairment`, a część technik przeniesiono (np. czyszczenie dziennika: T1070.001 → T1685.005, wyłączenie narzędzi ochrony: T1562.001 → T1685).
- **Sprawdzanie**: `siem-detector check` wypisuje `WARN` przy nieznanej technice, wycofanej technice (z następcą) i nieistniejącej taktyce; reguła działa dalej. Test reguły w panelu pokazuje te same ostrzeżenia, a test `TestRulesAttackTags` pilnuje reguł z repozytorium i wbudowanych.
- **Bez stałej techniki**: wykrycia antywirusa (Defender, ASR) dotyczą różnych technik zależnie od zagrożenia – takie reguły mają tag `vardr.attack_dynamic` zamiast `attack.t…` (test pokrycia ich nie wymaga).
- **Taktyki**: technika sama wskazuje swoje taktyki (kolumny macierzy), więc tag taktyki jest opcjonalny – pomaga tylko czytać regułę.
- **W panelu**: plakietki technik przy regułach i alertach (z linkiem do attack.mitre.org), filtr alertów po technice (`/alerts?technique=T1110` – z podtechnikami) i taktyce, macierz pokrycia (*Wykrywanie → MITRE ATT&CK*) z eksportem warstwy dla ATT&CK Navigator, technika w powiadomieniach o alertach. Kreator korelacji dopisuje korelacji tagi `attack.*` reguł, z których ją złożono.
- **Aktualizacja słownika** (nowa wersja ATT&CK, zwykle dwa razy w roku): pobierz `enterprise-attack.json` z `github.com/mitre-attack/attack-stix-data` i uruchom `go run ./tools/cmd/attackgen enterprise-attack.json > internal/attack/enterprise.json`, potem `siem-detector check rules`.

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

Nieobsługiwane i jawnie odrzucane (reguła nie działa „trochę”): agregacje Sigmy (`| count() by …`), `timeframe`, `near`, modyfikatory `base64offset`, `windash`, `wide` itp. Progi wyraża się przez `vardr.threshold`.

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

## Rozszerzenia Vardra

```yaml
vardr:
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
  i18n:                 # tłumaczenia (opcjonalnie)
    en:
      title: Series of failed logons to one account
      description: |
        …
      instructions: |
        …
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
| `i18n` | tytuł, opis i instrukcja w innych językach (obsługiwany: `en`). Panel pokazuje je kontom z tym językiem, powiadomienia – przy takim języku systemu (Powiadomienia → *Język systemu*). Brak tłumaczenia – tekst bazowy (polski). Instrukcja w tłumaczeniu używa tych samych zmiennych `{{…}}`. |

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
vardr:
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
- **`vardr`** – w regule korelacyjnej tylko `enabled`, `suppress` (domyślnie większe z 1 h i `timespan`), `instructions` i `i18n`. W instrukcji oprócz pól ostatniego zdarzenia są `{{count}}` (liczba zdarzeń), `{{window}}`, `{{rules}}` (tytuły reguł, które trafiły) i `{{key}}` (wartości `group-by`).

**Jak działa.** Detektor co minutę (razem z korelacjami wbudowanymi) szuka w `siem.events` kluczy z nowo przyjętych zdarzeń reguł bazowych. Dla tych kluczy pobiera zdarzenia z okna `timespan` wstecz (plus godzina na zdarzenia spóźnione) i sprawdza warunek. Alert dostaje silnik `correlation` i zawiera wszystkie zdarzenia, które spełniły korelację. Ponowne przebiegi nie dublują zdarzeń (para reguła–zdarzenie jest w alercie raz), a kolejne trafienia tego samego klucza w oknie `suppress` dołączają do otwartego alertu.

**Ograniczenia.** Bez warunków `lt`, `lte`, `eq`, `neq` (alert na „za mało” zdarzeń nie ma sensu przy ocenie nowych zdarzeń) i bez typu `value_sum`/`value_avg`. Reguła bazowa nie może być progowa (`vardr.threshold`) – próg wyraża sama korelacja. Najwięcej 50 000 zdarzeń jednej korelacji w przebiegu; ponad limit przebieg kończy się błędem w dzienniku detektora – zawęź reguły bazowe albo skróć okno. Korelacje wbudowane („udane po nieudanych”, „nowy kraj”) zostają w kodzie, bo wymagają historii spoza okna.

### Kreator korelacji w panelu

*Reguły detekcji → Nowa korelacja (kreator)* (rola `analyst`; zapis – `admin`) składa regułę korelacyjną z przykładowych zdarzeń:

1. **Zdarzenia.** Do 10 przykładów – z wyszukiwarki w kreatorze albo z Mímira (szczegóły zdarzenia → „Dodaj do kreatora korelacji”). Lista żyje w tej karcie przeglądarki.
2. **Kroki.** Dla każdego zdarzenia kreator pokazuje wdrożone reguły, które do niego pasują (reguły progowe nie mogą być bazą), albo proponuje nową regułę bazową z zaznaczonych pól (domyślnie rodzaj zdarzenia: `EventID`, a dla urządzeń `event.action` i `event.outcome`). Zdarzenia z tym samym wyborem to jeden krok; kolejność kroków – według czasu przykładów.
3. **Warunek.** Klucz to wartość, która występuje we wszystkich krokach (np. SID nowego konta jako `TargetSid` w 4720 i `MemberSid` w 4728 – kreator sam dopisze `aliases`). Jeden krok: wartość wspólna wszystkim przykładom, a do `value_count` pole, którego wartości się różnią. Typ i okno są podpowiadane (okno ≈ dwukrotność odstępu między przykładami).
4. **Opis i test.** Tytuł, poziom, opis, instrukcja, `generate` (gdy korelacja używa wdrożonych reguł, kreator domyślnie zostawia ich alerty). Wygenerowany YAML można poprawić ręcznie i przetestować na historii jak każdą regułę.

**Reguły z panelu** są zapisywane w Sadze (`gjallarhorn.panel_rules`), a detektor wczytuje je obok katalogu `rules/` jako plik `panel/<id korelacji>.yml` (w ciągu 30 s, bez wdrożenia). Mają historię wersji, włączanie i wyłączanie jak reguły z plików; administrator może je edytować (YAML) i usuwać (powód i hasło, audyt). Id reguł z panelu nie może powtarzać id reguł wdrożonych – przy konflikcie wygrywa plik z repozytorium. Dobrą regułę warto potem przenieść do repozytorium (`rules/correlation/`) i usunąć z panelu.

**Pola ze spacją w nazwie** (Microsoft Defender: `Threat Name`, `Severity Name`, `Process Name`, `Detection User`, `New Value`…) piszemy w selekcjach w apostrofach albo bez (`Threat Name|contains: Mimikatz`), w `group_by` i instrukcjach tak samo (`{{Threat Name}}`). Zdarzenia Defendera mają zbiór danych `windows.defender` (logsource `service: windefend`); agent zbiera je od wersji 0.7.2.

## Dobre praktyki

- **Grupuj po tym, co analityk zablokuje albo sprawdzi:** konto (brute force), adres (spraying), osoba (`user.identity` – próby z wielu źródeł), komputer (podejrzane procesy).
- **Wykluczenia jako osobne selekcje** (`computer_account`, `empty`, `local`) w warunku `and not …`, z opisem w `falsepositives`.
- **Instrukcja konkretna:** co sprawdzić, czym odróżnić fałszywy alarm, co zrobić przy prawdziwym incydencie.
- **Poziom wg skutku:** `critical` tylko dla zdarzeń niemal pewnych (np. wyczyszczony dziennik Security), `high` – wymaga reakcji w godzinach, `medium` – do przejrzenia, `low` – kontekst.
- **Reguła na wielu źródłach** (np. logowania w AD, Entra i na VPN) używa pól wspólnych (`event.outcome`, `user.identity`, `source.ip`) i warunku po `event.dataset`. Przykład: `rules/cross/password_spraying_multi_source.yml`.
- **Nie zmieniaj `id`** przy poprawkach – historia wersji i ustawienia z panelu są przypisane do `id`.

## Testowanie

1. **Lokalnie:** `go run ./server/cmd/siem-detector check rules` wczytuje wszystkie reguły i wypisuje błędy (`ERROR`, po angielsku; kod wyjścia 1). Panel pokazuje błędy reguł w języku konta.
2. **W panelu** (*Reguły detekcji → Test reguły*, rola `analyst`): wklejona reguła jest uruchamiana na zdarzeniach z ClickHouse z ostatnich 1–168 godzin. Widać trafienia, a dla reguł progowych – alerty, które by powstały. Regułę korelacyjną testuje się tak samo: wklejony tekst może zawierać też reguły bazowe (dokumenty po `---`), a brakujące są brane z wczytanych reguł; wynik to alerty z kluczem i zdarzeniami. Test korzysta z tych samych limitów co wyszukiwarka.
3. **Test zgodności silników** (`server/internal/detector/compat_test.go`): korpus zdarzeń (`testdata/`) przechodzi przez oba silniki, a test sprawdza, że każda reguła z `rules/` daje te same trafienia w locie i w SQL. Nowa reguła powinna mieć zdarzenie w korpusie, które ją wywołuje. Uruchomienie: [rozwoj.md](rozwoj.md#testy).
4. **W laboratorium:** wywołanie zdarzenia na prawdziwym źródle (np. nieudane logowania do DC, `fortisim -scenario vpn-brute`, `curl … entrasim/sim/scenario?name=spray`) i sprawdzenie alertu w Gjallarhornie.

## Wdrażanie

```bash
deploy/lab/deploy.sh rules
```

Skrypt najpierw sprawdza reguły (`siem-detector check`). Potem kopiuje je na VM do nowego katalogu `rules/v<czas>` i atomowo przełącza dowiązanie `rules/current`. Detektor wczytuje zmiany w ciągu 30 s bez restartu. Reguła z błędem nie zatrzymuje pozostałych: jest pomijana, a błąd widać w panelu i w alercie Grafany „Reguły detekcji z błędami”. Każda zmiana treści reguły to nowa wersja w historii (panel → reguła → Wersje).

**Włączanie i wyłączanie w panelu** (administrator, z powodem i hasłem) nadpisuje `enabled` z pliku i trafia do audytu. „Przywróć z pliku” cofa nadpisanie.

Lista reguł ma wyszukiwarkę (tytuł, id, plik, tag) i filtry: źródło (własne, SigmaHQ, z panelu, wbudowane), stan i poziom. Administrator może zaznaczyć reguły – także wszystkie z filtra – i zmienić je **zbiorczo**: włączyć, wyłączyć, ustawić tryb próbny albo przywrócić ustawienie z pliku. Zmiana zbiorcza zawsze wymaga powodu i hasła i trafia do audytu jednym wpisem.

### Tryb próbny

Reguła w trybie próbnym jest oceniana na bieżących zdarzeniach, ale **nie tworzy alertów ani powiadomień** – detektor liczy tylko trafienia: godzinami i komputerami, z ostatnim zdarzeniem jako przykładem. Wyniki są na stronie *Reguły detekcji → Próby reguł*:

| Ocena | Kiedy | Co zrobić |
|---|---|---|
| za krótko | próba trwa krócej niż dobę | poczekać |
| cicha | 0 trafień | można włączyć |
| rzadka | mniej niż 1 trafienie dziennie | przejrzeć przykłady, włączyć |
| umiarkowana | 1–20 dziennie | sprawdzić, czy to prawdziwe zdarzenia; ewentualnie wyjątki w regule |
| głośna | ponad 20 dziennie | bez dostrojenia nie włączać |

Typowy przebieg dla reguł SigmaHQ: filtr *SigmaHQ*, poziom *wysoki* i *krytyczny* → zaznacz wszystkie → *Tryb próbny*; po tygodniu–dwóch w *Próbach reguł* zaznacz ciche i rzadkie → *Włącz*, głośne → *Wyłącz*.

- Próby działają w silniku w locie (`SIEM_DETECTION_MODE` `stream` albo `both`). Reguły progowe liczą trafienia warunku, bez progu.
- Włączona reguła ustawiona jako próbna przestaje alarmować na czas próby – dlatego wymaga powodu i hasła jak wyłączenie.
- Trafienia leżą w `gjallarhorn.rule_trial_hits` 35 dni; ponowne rozpoczęcie próby liczy od zera.
- Próba nie dotyczy korelacji, reguł wbudowanych i reguł bazowych korelacji.

## Reguły wbudowane

Nie są plikami Sigmy – działają w kodzie detektora, ale są widoczne w panelu jak reguły (plik „(wbudowana)”):

| Reguła | Id | Co wykrywa | Wyłączana w panelu |
|---|---|---|---|
| Utrata łączności z agentem | `heimdall-agent-heartbeat-lost` | brak heartbeatu ponad próg grupy agentów; zamyka się sama po powrocie | nie (próg w grupie) |
| Próba sabotażu agenta | `heimdall-agent-tamper` | zatrzymanie bez tokenu, zmiana uprawnień usługi, zabicie procesu, fałszywy token, brak powrotu po aktualizacji | nie (ochrona w grupie) |
| Udane logowanie po serii nieudanych | `heimdall-success-after-failures` | ≥5 nieudanych logowań osoby w 30 min (dowolne źródła), potem udane; kolejne udane logowania przy otwartym alercie podbijają licznik | tak |
| Logowanie z nowego kraju | `heimdall-signin-new-country` | udane logowanie z kraju spoza historii osoby z 30 dni (Entra ID) | tak |
| Cisza źródła zdarzeń | `heimdall-source-silent` | urządzenie syslog albo chmura milczy dłużej niż najdłuższa przerwa z 7 dni + 1 h | tak |
| Ryzyko krytyczne osoby lub komputera | `vardr-risk-critical` | wynik ryzyka osoby albo komputera wchodzi w poziom krytyczny ([Ryzyko](panel.md#ryzyko-osób-i-komputerów)) | tak (także w ustawieniach ryzyka) |

Identyfikatory reguł sprzed zmiany nazwy mają przedrostek `heimdall-` – dawną nazwę projektu. Zostają bez zmian, bo wiążą historię alertów, filtry kanałów powiadomień i nadpisania z panelu.

Kod: `server/internal/detector/heartbeat.go`, `tamper.go`, `correlate.go`, `silence.go`, `riskrule.go` (scoring: `internal/risk`). Korelacje i cisza źródła czytają ClickHouse (`siem.auth_events`, `siem.events`), więc wymagają `SIEM_DETECTOR_CH_PASSWORD`.

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
| `windows/proc_discovery_burst.yml` | rozpoznanie: ≥4 różne narzędzia (whoami, net, nltest, systeminfo…) na komputerze w 10 min |
| `windows/proc_ad_discovery_tools.yml` | rozpoznanie AD: nltest /domain_trusts, `net group "domain admins"`, AdFind, BloodHound |
| `windows/system_service_remote_exec.yml` | przemieszczanie: usługa PsExec / Impacket (%COMSPEC%, ADMIN$) |
| `windows/proc_remote_exec_wmi_winrm.yml` | przemieszczanie: powłoka uruchomiona przez WMI (wmiprvse) albo WinRM (wsmprovhost) |
| `windows/security_ntlm_logon_many_hosts.yml` | przemieszczanie: logowania sieciowe NTLM jednego konta na ≥5 komputerach w 10 min |
| `windows/ps_script_collection.yml` | zbieranie: PowerShell ze zrzutem ekranu, schowkiem, przechwytywaniem klawiszy |
| `windows/proc_archive_with_password.yml` | zbieranie: archiwum 7-Zip/RAR z hasłem |
| `windows/proc_lolbin_download.yml` | C2: pobranie pliku przez certutil albo bitsadmin |
| `windows/proc_remote_access_tunnel.yml` | C2: AnyDesk, ScreenConnect, TeamViewer…, ngrok, chisel, plink -R |
| `windows/proc_exfil_cloud_tools.yml` | wynoszenie: rclone copy/sync, MEGA, curl --upload-file |
| `network/fortigate_port_scan.yml` | rozpoznanie: ≥20 odrzuconych portów z jednego adresu w 2 min |
| `windows/defender_threat_detected.yml` | Microsoft Defender wykrył zagrożenie (1116, 1006, podejrzane zachowanie 1015); alert na komputer i nazwę zagrożenia |
| `windows/defender_remediation_failed.yml` | Defender nie usunął zagrożenia (1008, 1118, 1119) – krytyczny |
| `windows/defender_protection_disabled.yml` | wyłączona ochrona w czasie rzeczywistym albo skanowanie (5001, 5010, 5012), zablokowana próba zmiany (5013) |
| `windows/defender_exclusion_added.yml` | dodane wykluczenie Defendera (5007 z `\Exclusions\`) |
| `windows/defender_asr_block.yml` | reguła ASR zablokowała działanie (1121) |
| `network/fortigate_host_sweep.yml` | rozpoznanie: ≥30 odrzuconych adresów docelowych z jednego adresu w 2 min |

| `correlation/new_account_privileged.yml` | korelacja: konto utworzone i w ciągu godziny dodane do grupy uprzywilejowanej |
| `correlation/account_failures_many_sources.yml` | korelacja: nieudane logowania na jedno konto z ≥4 adresów w 15 min (z regułą bazową) |

Taktyka *Resource Development* (przygotowanie infrastruktury napastnika – domeny, serwery, konta poza firmą) nie ma reguł: nie zostawia śladów w logach organizacji. Reguły skanowania na FortiGate wymagają logowania odrzuconego ruchu w polityce zapory.

Wszystkie reguły z repozytorium mają tłumaczenie na angielski (`vardr.i18n.en`); pilnuje tego test `TestOwnRulesTranslated`.

## Import reguł SigmaHQ

[SigmaHQ](https://github.com/SigmaHQ/sigma) to otwarta baza kilku tysięcy reguł Sigma utrzymywana przez społeczność. Vardr obsługuje podzbiór Sigmy, więc część reguł się wczyta, a część nie (np. nieobsługiwane modyfikatory albo źródła, których agent nie zbiera). Import jest ręczny: kopiujesz wybrane katalogi, sprawdzasz je parserem Vardra, odrzucasz te, które nie przechodzą, i wdrażasz resztę **wyłączoną**. Potem włączasz pojedyncze reguły w panelu, po teście na historii.

Reguły trafiają do `rules/sigmahq/`. Paczka instalacyjna serwera ich nie zawiera – import to decyzja administratora.

### Serwer z instalatora

Na serwerze zainstalowanym z paczki (`install.sh`) cały import wykonuje jeden skrypt – bez repozytorium i Go:

```bash
sudo /opt/vardr/sigmahq-import.sh            # import albo aktualizacja
sudo /opt/vardr/sigmahq-import.sh --remove   # usunięcie reguł SigmaHQ
```

Skrypt pobiera SigmaHQ z GitHuba, kopiuje kategorie z listy poniżej, odrzuca reguły `experimental`, `deprecated` i `unsupported` oraz te, których parser Vardra nie obsługuje, wyłącza resztę w plikach, dodaje informację o źródle i licencji i przełącza nową wersję katalogu reguł (detektor wczyta ją w ciągu 30 s). Aktualizacja Vardra przenosi zaimportowane reguły do nowej wersji. Ta sama instrukcja jest w panelu: *Reguły → Import reguł SigmaHQ*.

### Repozytorium Vardra

Testy Vardra (zgodność silników, korpus, tagi ATT&CK) ten katalog pomijają, a `TestImportedRules` pilnuje, żeby zaimportowane reguły wczytywały się bez błędów i były w plikach wyłączone.

### Kroki – PowerShell (w katalogu projektu)

1. Pobranie (albo aktualizacja: `git -C ../sigma pull`):

   ```powershell
   git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma
   ```

2. Kopiowanie kategorii dla źródeł, które zbieramy (przy aktualizacji najpierw `Remove-Item -Recurse rules/sigmahq` – włączenia z panelu zostają, bo są zapisane po `id` reguły):

   ```powershell
   $dirs = 'windows/process_creation','windows/powershell/powershell_script','windows/builtin/security','windows/builtin/system','windows/builtin/windefend','windows/network_connection','windows/file/file_event','windows/dns_query','windows/registry/registry_set','cloud/azure/signin_logs','cloud/azure/audit_logs'; foreach ($d in $dirs) { $src = "../sigma/rules/$d"; if (Test-Path $src) { New-Item -ItemType Directory -Force "rules/sigmahq/$d" | Out-Null; Copy-Item "$src/*" "rules/sigmahq/$d/" -Recurse -Force } }
   ```

3. Tylko reguły dojrzałe (status `stable` i `test`):

   ```powershell
   Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | Where-Object { Select-String -Path $_.FullName -Pattern '^status: (experimental|deprecated|unsupported)' -Quiet } | Remove-Item
   ```

4. Sprawdzenie parserem i usunięcie reguł, których Vardr nie obsługuje (drugie polecenie; potem pierwsze jeszcze raz – licznik błędów ma pokazać 0):

   ```powershell
   & "C:\Program Files\Go\bin\go.exe" run ./server/cmd/siem-detector check rules > check.txt; "OK: " + (Select-String -Path check.txt -Pattern '^OK').Count; "błędy: " + (Select-String -Path check.txt -Pattern '^(?!OK|WARN)\S+\s+sigmahq/').Count
   ```

   ```powershell
   Select-String -Path check.txt -Pattern '^(?!OK|WARN)\S+\s+(sigmahq/[^\s:]+\.yml)' | ForEach-Object { "rules/" + $_.Matches[0].Groups[1].Value } | Sort-Object -Unique | Where-Object { Test-Path $_ } | Remove-Item
   ```

5. Wszystkie zaimportowane reguły wyłączone w plikach (bez tego włączyłyby się setki reguł naraz):

   ```powershell
   Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | ForEach-Object { [IO.File]::AppendAllText($_.FullName, "`nvardr:`n  enabled: false`n") }
   ```

6. Wdrożenie (skrypt bashowy – przez Git Bash):

   ```powershell
   & "C:\Program Files\Git\bin\bash.exe" deploy/lab/deploy.sh rules
   ```

### Kroki – Git Bash

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma
for d in windows/process_creation windows/powershell/powershell_script windows/builtin/security windows/builtin/system windows/builtin/windefend windows/network_connection windows/file/file_event windows/dns_query windows/registry/registry_set cloud/azure/signin_logs cloud/azure/audit_logs; do [ -d "../sigma/rules/$d" ] && mkdir -p "rules/sigmahq/$d" && cp -r "../sigma/rules/$d/." "rules/sigmahq/$d/"; done
grep -rlE '^status: (experimental|deprecated|unsupported)' rules/sigmahq | xargs -r rm
go run ./server/cmd/siem-detector check rules > check.txt
grep -vE '^(OK|WARN)' check.txt | sed -nE 's/^[^ ]+ +(sigmahq\/[^ :]+\.yml).*/rules\/\1/p' | sort -u | xargs -r rm
find rules/sigmahq -name '*.yml' -exec sh -c 'printf "\nvardr:\n  enabled: false\n" >> "$1"' _ {} \;
deploy/lab/deploy.sh rules
```

### Włączanie reguł

Najwygodniej przez [tryb próbny](#tryb-próbny): zaznacz reguły SigmaHQ (np. poziom wysoki i krytyczny), ustaw próbę, a po tygodniu–dwóch włącz te, które okazały się ciche albo rzadkie. Pojedynczą regułę sprawdzisz też od razu na historii: zakładka **Test** w szczegółach reguły (zdarzenia z ostatnich 7 dni). Reguła bez fałszywych alarmów – włącz przełącznikiem (administrator, wpis w audycie). Ustawienie z panelu przetrwa ponowny import, bo jest zapisane po `id` reguły. Silniki oceniają tylko reguły włączone – wyłączone nie obciążają detekcji.

Kategorie Sysmona spoza listy w kroku 2 (ładowanie bibliotek, dostęp do procesów, potoki, WMI) pomijamy: agent ich nie zbiera, a silnik ich nie obsługuje. Reguły na Event ID, których profil agenta nie zbiera, wczytają się, ale nie będą miały trafień – test na historii to pokaże (0 zdarzeń).

### Licencja

Reguły SigmaHQ są na licencji [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License): wolno je używać, zmieniać i rozpowszechniać, także komercyjnie, pod warunkiem zachowania autora (pole `author`), wskazania źródła i licencji. Nie usuwaj z reguł pól `author` i `references`. Dla reguł z `rules/sigmahq/` panel pokazuje autora, źródło (odnośnik do reguły w SigmaHQ) i licencję w szczegółach reguły i alertu, a powiadomienia mają pole „Autor reguły” – licencja wymaga wskazania autora także w komunikatach z trafień. Reguły Vardra tego pola nie mają. Katalog `rules/sigmahq/` jest w `.gitignore`, a paczka instalacyjna go pomija: decyzja o imporcie należy do administratora, a reguły nie są dystrybuowane z Vardrem. `sigmahq-import.sh` zapisuje w tym katalogu informację o źródle i licencji (`README.md`, `LICENSE.SigmaHQ.md`); przy imporcie z repozytorium dodaj ją sam, jeśli przekazujesz katalog dalej. Licencja reguł nie dotyczy kodu Vardra.
