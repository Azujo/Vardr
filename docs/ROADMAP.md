# Roadmapa własnego systemu SIEM

Wersja planistyczna 1.7.0 • 26.10.2026 (plan wersji po 1.0: sekcja 17a, wersja 1.6: sekcja 17b)

## Decyzje ustalone (06.10.2026)

| Decyzja | Ustalenie | Szczegóły |
|---|---|---|
| Backend magazynu zdarzeń | **ClickHouse** (zmiana z OpenSearch: odporność na duży wolumen, kompresja, szybkie agregacje); dostęp przez warstwę abstrakcji | Sekcje 15, 15a |
| Kontrakt paczki agent → serwer | `HTTPS POST /v1/ingest` po mTLS, JSON skompresowany gzip/zstd, surowe logi, ACK po trwałym zapisie | Załącznik A |
| Retencja w laboratorium | Kolejka NATS: tylko nieprzetworzone wiadomości, limit rozmiaru zamiast wieku (zmiana 1.3.3, ustalenie K1) • Magazyn zdarzeń ClickHouse: **5 dni** • Archiwum NIS2: **30 dni** | Sekcje 5, 6 |
| Domyślna lista zdarzeń Windows | Lista kanałów i Event ID, konfigurowalna per grupa agentów | Załącznik B |
| Konsola zarządzania | **Własny panel** (React + TypeScript, backend `siem-api` w Go, PostgreSQL) w stylu Wazuh Dashboard; Grafana zostaje do monitorowania samego SIEM | Załącznik C |
| Wdrażanie agentów | **Rejestracja tokenem**: panel generuje token i instalator bez klucza prywatnego; agent sam tworzy klucz i otrzymuje certyfikat od serwera. Paczki z kluczem (`siem-pki package`) tylko w laboratorium | Załącznik C |
| Kolejność etapów | Panel (moduły: logowanie, agenci, wdrażanie, zdarzenia) razem z etapem 2 **przed** detekcją | Sekcja 17 |
| Nazwa i nazewnictwo | Produkt: **Vardr** (repozytorium `vardr`). Komponenty nazwane według mitologii nordyckiej w panelu, dokumentacji i nazwach usług; w kodzie nazwy opisowe | Załącznik D |
| Skalowanie | Elementy bez stanu (ingest, normalizator, writer, później detekcja) **poziomo** – dokładanie kopii; elementy z danymi (NATS, ClickHouse) **najpierw pionowo**, potem klaster. Przeciążenie ma kończyć się opóźnieniem, nigdy utratą danych | Załącznik E |

## 0. Co zmieniło się względem wersji 1.1

- Projekt jest **własny, rozwijany po godzinach przez jedną osobę**. Firma (ok. 2000 osób, ok. 3500 agentów, obecnie ELK SIEM) służy jako wzorzec środowiska, a nie jako miejsce wdrożenia produkcyjnego.
- **Windows jako pierwszy system**, Linux później.
- Skala docelowa rośnie z 1000 EPS do szacunkowych **5 000–15 000 EPS** (do zmierzenia).
- Nowa, niezależna oś konfiguracji: **`raw_archive`**, czyli archiwum oryginalnych logów pod wymagania NIS2, dostępne w obu profilach analizy.
- Nowe wyróżniki produktu: **edytor dekoderów w panelu**, **agent odporny na wyłączenie i deinstalację** (w realnych granicach), **agent jako kolektor syslog**, **mapowanie tożsamości** do korelacji.
- Lista integracji z priorytetami. Pierwsze trzy: **Windows/AD, FortiGate, Entra ID/M365**.
- Detekcja budowana **funkcjami w obu silnikach jednocześnie**, z testami zgodności, a język reguł MVP ograniczony do tego, co oba silniki wykonują identycznie.
- Harmonogram w **godzinach pracy**, przeliczony na pracę po godzinach.

## 1. Cel projektu

**Cele:**

1. Zbudować działający SIEM, w którym administrator wybiera sposób działania:
   - **profil wydajnościowy (jak Wazuh)**: analiza w locie, do indeksu trafiają alerty;
   - **profil pełny (jak Elastic Security)**: wszystkie zdarzenia w indeksie, reguły wykonywane cyklicznie na indeksie.
2. Niezależnie od profilu zapewnić możliwość **archiwizacji oryginalnych logów w sposób wspierający wymagania NIS2**.
3. Zweryfikować system w laboratorium odwzorowującym firmę: Windows/AD, IIS, FortiGate, Entra ID/M365, oraz w teście obciążenia symulującym ok. 3500 agentów.

**Nie-cele tej roadmapy:**

- zastąpienie produkcyjnego ELK SIEM w firmie;
- automatyczna reakcja na endpointach (izolacja hosta, blokowanie kont);
- obsługa wielu organizacji (multi-tenancy). Pole `siem.tenant_id` zostaje w schemacie, ale izolacja nie jest implementowana.

**Dodatkowy cel poznawczy:** w laboratorium porównać wyniki detekcji własnego systemu z Elastic Security na tych samych danych.

## 2. Założenia

| Obszar | Założenie | Uwagi |
|---|---|---|
| Środowisko wzorcowe | ~2000 pracowników, ~3500 agentów (stacje, serwery, urządzenia sieciowe) | Witryny na Kentico i IIS |
| Obciążenie | 5 000–15 000 EPS średnio, wyższe szczyty | Szacunek, patrz sekcja 3 |
| Pierwszy system | Windows (stacje, serwery, kontrolery domeny) | Linux w późniejszym etapie |
| Wykonawca | 1 osoba, po godzinach, ok. 10–15 h tygodniowo | Harmonogram w godzinach, sekcja 17 |
| Języki | Go (rdzeń, agent), Python (konektory API, narzędzia, dane testowe) | C++ niepotrzebny |
| Wdrożenie | Laboratorium on-premises (VM + kontenery) | HA poza zakresem MVP |
| Tryb pracy | Detekcja i analiza, bez automatycznej reakcji | |

## 3. Szacunek obciążenia

| Źródło | Ilość | EPS (orientacyjnie) |
|---|---|---|
| Stacje Windows z polityką audytu (+ Sysmon) | ~2000–2500 | 2 000–5 000 |
| Serwery, w tym IIS | kilkaset | 2 000–5 000 |
| Kontrolery domeny | kilka | 500–2 000 |
| FortiGate, F5, GreyCortex | kilka–kilkanaście | 1 000–5 000 |
| **Razem** | | **~5 000–15 000** |

Przy 10 000 EPS i średnio ~1 KB na zdarzenie: **~864 GB surowych danych dziennie**, ok. 26 TB przez 30 dni, przed narzutem indeksu i replikami. Wzór i metodyka z wersji 1.1 (sekcja 13) pozostają aktualne.

Wnioski projektowe:

- Profil pełny przy indeksowaniu wszystkiego wymaga realnego klastra. To uzasadnia profil wydajnościowy i tanie archiwum obiektowe.
- **Filtrowanie u źródła** jest elementem produktu: przemyślana polityka audytu i lista Event ID w konfiguracji agenta.
- Laboratorium nie odtworzy tego ruchu z VM. Potrzebny jest **generator obciążenia** symulujący tysiące agentów (sekcja 16).

## 4. Kluczowe cechy produktu

| Cecha | Opis | Sekcja |
|---|---|---|
| Wybór profilu analizy | Strumieniowy albo indeksowy, ten sam model reguł i alertów | 5, 11 |
| Archiwum NIS2 | Oryginalne logi, ochrona przed modyfikacją, retencja, weryfikacja integralności | 6 |
| Lekki agent z ochroną | Tylko zbieranie logów, bufor offline, token deinstalacji, wykrywanie wyłączenia | 7 |
| Agent jako kolektor | Przyjmuje syslog z urządzeń sieciowych i przesyła dalej szyfrowanym kanałem | 7, 9 |
| Edytor dekoderów | Użytkownik mapuje fragmenty nieznanego logu na pola, z testem na próbce | 10 |
| Korelacja tożsamości | Jedna osoba / host rozpoznawana w AD, Entra, EDR i firewallu | 12 |

## 5. Architektura i konfiguracja

### Przepływ

```
źródła (Event Log, pliki, syslog)        API chmurowe (Entra, M365, S1)
        │                                          │
     agent (bufor, mTLS)                  konektory API (Python/Go)
        └──────────────┬───────────────────────────┘
                       ▼
            endpoint przyjmujący (mTLS, ACK po trwałym zapisie)
                       ▼
            NATS JetStream: strumień surowy
               ├──► archiwizator ──► magazyn obiektowy WORM + łańcuch hashy   [raw_archive]
               └──► normalizator + dekodery ──► strumień zdarzeń   (błędy → kwarantanna)
                                                   ├──► [stream] silnik w locie ──┐
                                                   └──► zapis paczkami ──► ClickHouse │
                                                          └──► [index_query] harmonogram reguł
                                                                                  ▼
                                                   PostgreSQL: alerty + outbox ──► powiadomienia
```

Strumień surowy i strumień zdarzeń mają **niezależnych odbiorców** (każdy widzi wszystkie dane), a nie wspólną kolejkę roboczą. Zasada z wersji 1.1 pozostaje bez zmian.

### Trzy niezależne osie konfiguracji

| Oś | Wartości | Znaczenie |
|---|---|---|
| `detection_mode` | `stream` / `index_query` | Gdzie wykonują się reguły |
| `event_storage` | `alerts_only` / `selected` / `indexed_events` | Co trafia do indeksu wyszukiwania |
| `raw_archive` | `off` / `on` (+ polityka per źródło) | Archiwum oryginałów pod NIS2 |

### Profile w instalatorze

| | **Wydajnościowy (jak Wazuh)** | **Pełny (jak Elastic)** |
|---|---|---|
| `detection_mode` | `stream` | `index_query` |
| `event_storage` | `alerts_only` | `indexed_events` |
| `raw_archive` | wybór użytkownika | wybór użytkownika |

Zakładka zaawansowana pozwala łączyć osie dowolnie, np. `stream` + `indexed_events`. Przejście z profilu wydajnościowego na pełny może **zaindeksować historię z archiwum**, jeśli archiwum było włączone.

### Gdzie ustawiany jest przełącznik NIS2

- **Config serwera / instalator** określa, czy archiwum *może* działać: backend (dysk lokalny, później magazyn S3 z Object Lock), poświadczenia, tryb blokady (WORM), maksymalna i minimalna retencja.
- **Panel** określa politykę: włączenie, retencję, wybór źródeł objętych archiwum.
- Zasady:
  - włączenie jest proste, a **wyłączenie lub skrócenie retencji wymaga ponownego uwierzytelnienia** (docelowo z MFA), trafia do audytu i generuje alert systemowy;
  - wyłączenie zatrzymuje archiwizację **nowych** logów, a dane już zarchiwizowane pozostają do końca retencji;
  - panel pokazuje stan zgodności: archiwum aktywne, wynik ostatniej weryfikacji integralności, źródła bez archiwizacji.

## 6. Archiwum NIS2

**Zakres funkcji:**

- Zapis **oryginalnych** paczek logów (przed normalizacją), skompresowanych, w magazynie obiektowym.
- **Blokada usuwania i modyfikacji** (Object Lock w trybie compliance lub governance) na czas retencji.
- **Łańcuch hashy**: każda paczka ma sumę SHA-256, a manifest okresowy (np. godzinowy) zawiera sumy paczek i hash poprzedniego manifestu. Manifesty są dodatkowo zapisywane w PostgreSQL. Usunięcie lub podmiana paczki są wykrywalne.
- **Okresowa weryfikacja integralności** z wynikiem widocznym w panelu i alertem przy niezgodności.
- **Polityka per źródło**: które źródła są archiwizowane i z jaką retencją.
- **Audyt dostępu** do archiwum: kto, kiedy, jaki zakres. Oddzielenie uprawnień administratora aplikacji od możliwości kasowania archiwum.
- **Eksport dla audytora**: wybrany zakres czasu i źródeł z manifestem i sumami kontrolnymi.
- **Re-indeksacja / replay** z archiwum do osobnego strumienia, domyślnie bez powiadomień produkcyjnych.
- **Synchronizacja czasu**: agent raportuje stan synchronizacji zegara, a zdarzenia mają `siem.time_quality`.

**Ustalenia wdrożeniowe (1.6, 07.10.2026):**

- **Magazyn:** w laboratorium dysk lokalny, a ochrona polega na wykrywaniu zmian łańcuchem hashy. MinIO od 2025 r. nie publikuje obrazów, więc blokada WORM dojdzie z backendem S3 (AWS, Wasabi, Backblaze, firmowy S3) w trybie **compliance**.
- **Archiwizator** (`siem-archiver`) to osobny trwały odbiorca `SIEM_RAW`:
  - paczka jest potwierdzana dopiero po zapisie segmentu (`fsync`, plik tylko do odczytu, wpis w spisie);
  - zatrzymany archiwizator powoduje zator i odmowę 503, a nie lukę w archiwum;
  - działa tylko jedna kopia, pilnowana blokadą doradczą w PostgreSQL.
- **Format:** segmenty paczek z jednej godziny archiwizacji. Każda paczka ma metadane i SHA-256.
- **Manifest godzinowy:** lista segmentów z SHA-256, liczbą paczek i rozmiarem oraz hash poprzedniego manifestu. Manifest leży na dysku i w Sadze (schemat `urd`).
  - Pusta godzina też dostaje manifest.
  - Wpisy manifestów nie znikają po retencji (tylko znacznik wygaśnięcia), więc łańcuch da się sprawdzić od początku.
- **Weryfikacja** (co 6 h) wykrywa:
  - zmianę bajtu i ucięcie lub usunięcie segmentu;
  - dodanie pliku;
  - podmianę manifestu na dysku lub w bazie;
  - usunięcie manifestu ze środka łańcucha;
  - usunięcie końca łańcucha (brak nowych manifestów przez ponad 2 h).
- **Granica ochrony:** napastnik z pełnym dostępem do dysku i bazy może przeliczyć cały łańcuch. Odpowiedź na to to zapisywanie hasha ostatniego manifestu poza systemem (np. w alertach lub u audytora) i backend z Object Lock.
- **Duplikaty:** archiwum działa w trybie „co najmniej raz”. Ponowione dostarczenie po awarii daje drugą kopię paczki z tym samym `batch_id`, którą odfiltrowuje replay i eksport.

**Uwagi prawne (do potwierdzenia):** NIS2 i rozporządzenie wykonawcze 2024/2690 opisują logowanie ogólnie: kategorie zdarzeń, ochrona przed zmianą, ustalona retencja, synchronizacja czasu. Konkretne okresy zależą od krajowej implementacji (nowelizacja ustawy o KSC) i od sektora. Domyślną retencję w produkcie należy uzgodnić z audytorem. W laboratorium przyjmujemy 30 dni dla archiwum (indeks: 5 dni, kolejka: 1–2 dni).

Logi zawierają dane osobowe pracowników. Wdrożenie w firmie wymagałoby uzgodnienia celu, retencji i dostępu z IOD. System powinien to wspierać przez RBAC, retencję i audyt.

## 7. Agent

### Zakres

Agent **tylko zbiera, opisuje pochodzenie, buforuje i wysyła logi**. Nie wykonuje poleceń zdalnych, nie analizuje zdarzeń i nie jest powłoką administracyjną.

### Windows (pierwszy)

- Usługa Windows w Go, jeden plik binarny.
- Event Log przez subskrypcje z **bookmarkami** (wevtapi: EvtSubscribe, EvtRender, EvtCreateBookmark). Kanały: Security, System, Application, PowerShell/Operational, Sysmon/Operational.
- Pliki tekstowe z obsługą rotacji, np. **logi IIS w formacie W3C**.
- **Filtrowanie u źródła**: lista Event ID i kanałów w konfiguracji pobieranej z serwera.
- Wytyczne do polityki audytu (GPO) i konfiguracji Sysmon dostarczane w dokumentacji. Agent nie włącza brakującej telemetrii sam.

### Bufor offline

- **Najpierw dziennik źródła jako bufor**: bez połączenia agent nie przesuwa bookmarka i po powrocie czyta od miejsca, w którym skończył.
- **Bufor dyskowy** dla źródeł, które mogą nadpisać dane (rotacja plików, przepełnienie Event Logu) i dla trybu kolektora syslog.
- Usuwanie z bufora dopiero po **potwierdzeniu trwałego przyjęcia** przez serwer.
- Konfigurowalny **limit bufora** (np. 1 GB lub X% dysku) i polityka przepełnienia (usuwanie najstarszych / wstrzymanie). Licznik strat zgłaszany serwerowi po połączeniu.
- **Szyfrowanie bufora na dysku** (Windows: DPAPI w kontekście konta usługi), ACL ograniczające dostęp.

### Ochrona przed wyłączeniem i deinstalacją

Pełnej blokady nie da się zapewnić: lokalny administrator lub SYSTEM zawsze może zatrzymać proces, a ochrona na poziomie jądra (ELAM/PPL) wymaga certyfikacji Microsoft. Cel: **utrudnić i wykryć**.

- Zawężony deskryptor bezpieczeństwa usługi (zwykli użytkownicy i część narzędzi nie zatrzymają usługi).
- Automatyczny restart po awarii (recovery actions).
- **Deinstalacja wymaga tokenu**: osobnego, jednorazowego dla każdego agenta, generowanego w panelu i zapisywanego w audycie. Na endpoincie przechowywany jest tylko hash.
- Agent zgłasza próbę zatrzymania lub deinstalacji, jeśli zdąży.
- **Serwer alarmuje** przy braku heartbeatu, przerwie w danych ze źródła, zmianie stanu usługi (np. Event ID 7036/7040) i wyczyszczeniu dziennika (Event ID 1102).
- Jedno wspólne hasło administratora SIEM nie jest używane do deinstalacji, bo jego wyciek odblokowuje wszystkie stacje naraz.

### Zarządzanie flotą (3500 agentów)

- Instalator **MSI z cichą instalacją** i tokenem rejestracyjnym. Wdrażanie przez GPO, Intune lub SCCM.
- Rejestracja: jednorazowy token → wygenerowanie klucza na hoście → podpisanie certyfikatu przez serwer.
- **Grupy agentów** (stacje, serwery, DC, kolektory) z osobnymi konfiguracjami.
- Konfiguracja wersjonowana, pobierana przez połączenie inicjowane przez agenta.
- Status każdego źródła (uprawnienia, opóźnienie, błędy), a nie tylko heartbeat procesu.
- Kontrolowane aktualizacje z podpisanymi paczkami i rollbackiem (przed produkcją).

### Tryb kolektora

Agent zainstalowany na wybranym hoście w sieci urządzeń przyjmuje **syslog (UDP/TCP/TLS)** lokalnie i przesyła go dalej po mTLS, z buforem offline. Dzięki temu nieszyfrowany syslog nie przechodzi przez sieć do serwera, a urządzenia sieciowe korzystają z tej samej niezawodności co agenci.

### Linux (później)

journald z kursorem, pliki z rotacją, auditd. Pakiety deb/rpm, usługa systemd.

### Budżet zasobów (cel laboratoryjny do zmierzenia)

Poniżej 100 MiB RSS i średnio poniżej 2% jednego rdzenia przy 100 EPS na stacji. Sysmon zwiększa koszt na endpoincie niezależnie od agenta.

## 8. Komunikacja i tożsamość

- **mTLS, TLS 1.3**: osobny certyfikat dla każdego agenta i konektora, weryfikacja serwera, krótkie certyfikaty z automatyczną rotacją, lista unieważnień.
- Tożsamość agenta wynika z certyfikatu i rejestru po stronie serwera, nie z pól w przesyłanym logu.
- Szyfrowanie również między usługami serwera w sieci, szyfrowanie dysków i archiwum.
- Agent nie wymaga portu przychodzącego. Wszystkie połączenia inicjuje on sam.

## 9. Źródła i integracje

| Źródło | Sposób | Komponent | Priorytet |
|---|---|---|---|
| **Windows / AD (DC, serwery, stacje)** | Agent: Event Log, Sysmon | Agent Windows | **MVP – 1** |
| **FortiGate** | Syslog (key=value) przez agenta-kolektora | Kolektor + dekoder | **MVP – 2** |
| **Entra ID / M365** | API: Microsoft Graph (logi logowań i audytu), Office 365 Management Activity API | Konektor API | **MVP – 3** |
| IIS | Agent: pliki W3C | Agent + dekoder | v1 |
| SentinelOne | API (zdarzenia, alerty) lub syslog | Konektor API | v1 |
| F5 | Syslog / High Speed Logging | Kolektor + dekoder | v1 |
| Forcepoint DLP | Syslog (CEF) | Kolektor + dekoder | v1 |
| GreyCortex Mendel | Syslog | Kolektor + dekoder | v1 |
| Kentico | Dziennik zdarzeń w bazie danych (do potwierdzenia dla posiadanej wersji) | Konektor SQL | v2 |
| Linux | Agent: journald, pliki, auditd | Agent Linux | v1 |

**Konektory API:**

- osobne procesy (Python lub Go) z certyfikatem jak agent, wysyłające do tego samego endpointu;
- trwały kursor (ostatni pobrany znacznik czasu / token), obsługa limitów (429, Retry-After), paginacji i opóźnień po stronie dostawcy;
- sekrety (client secret / certyfikat aplikacji) w magazynie sekretów, nigdy w logach.

**Uwagi do Entra/M365:** wymagana rejestracja aplikacji w tenancie i zgoda administratora. Część logów logowania przez API wymaga licencji Entra ID P1/P2. Do laboratorium potrzebny jest testowy tenant z odpowiednią licencją lub trialem.

## 10. Normalizacja i edytor dekoderów

### Model

- Wersjonowany podzbiór **ECS** + przestrzeń `siem.*` (pola z wersji 1.1, sekcja 7).
- Każdy dekoder ma: ID, wersję, **warunek dopasowania** (źródło, `event.dataset`, nazwa programu, prefiks), typ parsera, mapowanie pól, transformacje (np. parsowanie czasu, konwersja typów), właściciela.
- Logi bez dekodera lub z błędem parsowania trafiają do **kwarantanny** z oryginałem i powodem.

### Typy dekoderów (w kolejności implementacji)

1. JSON: automatyczne rozpoznanie pól, użytkownik tylko mapuje je na ECS.
2. key=value: FortiGate i wiele urządzeń sieciowych.
3. Rozdzielane (CSV, TSV, spacje z nagłówkiem): logi IIS W3C (`#Fields`).
4. CEF / LEEF: Forcepoint, F5, wiele produktów bezpieczeństwa.
5. Syslog RFC 3164 / 5424 jako warstwa zewnętrzna, z dekoderem treści wewnątrz.
6. Regex / grok dla wolnego tekstu.

### Edytor w panelu

1. Panel pokazuje logi z kwarantanny pogrupowane według źródła i podobieństwa, np. „2000 nieznanych logów z 10.0.5.1”.
2. Użytkownik wybiera przykładowy log. System rozpoznaje format i proponuje podział na fragmenty.
3. Użytkownik zaznacza fragmenty i przypisuje je do pól (`source.ip`, `host.name`, `event.action`, `message` itd.). Panel podpowiada pola ECS i waliduje typ (np. czy fragment jest adresem IP).
4. **Test na próbce**: dekoder uruchamiany na ostatnich np. 500 logach ze źródła, z wynikiem w rodzaju „pasuje 487/500” i listą niepasujących.
5. Zapis wersji → publikacja → opcjonalne **ponowne przetworzenie kwarantanny**.

### Zasady bezpieczeństwa

- Dekoder to dane, nie kod. Bez skryptów i bez wywołań zewnętrznych.
- Regex w silniku RE2 (Go `regexp`, czas liniowy, odporność na ReDoS), limity długości wzorca, liczby pól i rozmiaru wpisu.
- Testy kontraktowe dla dekoderów wbudowanych na próbkach z repozytorium.

Wbudowane dekodery dla integracji z sekcji 9 są dostarczane z produktem. Edytor służy do pozostałych źródeł i lokalnych poprawek.

## 11. Detekcja

### Format reguł

- **Sigma (YAML) jako model logiczny** z własnymi polami rozszerzeń: `siem.execution_mode`, wyciszenie, klucz deduplikacji, właściciel, instrukcja analizy.
- Dwa kompilatory w Go:
  - do **drzewa predykatów** wykonywanego w silniku strumieniowym;
  - do **zapytań i agregacji** dla indeksu.
- Nieobsługiwane konstrukcje Sigma są jawnie odrzucane przy imporcie.
- Python (pySigma, SigmaHQ) może służyć jako narzędzie pomocnicze do testów i porównań, ale nie w ścieżce wykonania.

### Język reguł MVP

Tylko konstrukcje wykonywane **identycznie w obu silnikach**:

1. dopasowanie pojedynczego zdarzenia (warunki na polach, AND/OR/NOT, listy, ograniczony zestaw operatorów);
2. progi: `count` i `count distinct` w oknie czasowym z kluczem grupowania.

Sekwencje, korelacje między źródłami i reguły na historii dochodzą w v1. Wtedy pojawia się realna potrzeba oznaczania zgodności `stream` / `index_query` / `both`.

### Kolejność budowy

Budowa **funkcjami, nie silnikami**:

1. pojedyncze zdarzenie w obu silnikach + test zgodności;
2. progi w obu silnikach + test zgodności;
3. dopiero potem rozszerzenia.

**Zestaw testów zgodności** powstaje przed drugim silnikiem: uporządkowany zbiór zdarzeń + oczekiwane alerty, uruchamiany w CI na obu silnikach. Różnice muszą być udokumentowane w semantyce reguły.

Szczegóły checkpointów, zakładek czasowych, watermarków i deduplikacji: wersja 1.1, sekcje 6 i 8.

### Pierwsze scenariusze detekcji (do laboratorium)

| Scenariusz | Źródła |
|---|---|
| Brute force na konto domenowe (4625) | Windows/AD |
| Password spraying (wiele kont z jednego źródła) | Windows/AD, Entra ID |
| Dodanie konta do grupy uprzywilejowanej (4728/4732/4756) | Windows/AD |
| Wyczyszczenie dziennika zdarzeń (1102) | Windows |
| Podejrzane uruchomienie PowerShell (zakodowane polecenia) | Sysmon / PowerShell |
| Seria nieudanych logowań VPN | FortiGate |
| Logowanie z nowego kraju / nietypowej lokalizacji | Entra ID |
| Utrata heartbeatu agenta lub przerwa w źródle | System SIEM |

## 12. Korelacja i tożsamość encji

Korelacja między źródłami wymaga **mapowania encji**:

- **Użytkownik**: `DOMENA\jkowalski` (AD) ↔ `jan.kowalski@firma.pl` (Entra) ↔ zapis w EDR i VPN. Źródło mapowania: AD/Entra (`sAMAccountName`, UPN, `objectSid`, `onPremisesSecurityIdentifier`), uzupełniane ręcznie.
- **Host**: nazwa NetBIOS ↔ FQDN ↔ `host.id` agenta ↔ ID w EDR.
- **Adres IP ↔ host w czasie**: na podstawie DHCP, VPN i logów agenta. Przypisanie jest ważne w przedziale czasu.

Normalizator dopisuje pola wzbogacone, np. `user.siem_id` i `host.siem_id`, więc reguły korelacyjne operują na jednej tożsamości. Mapowanie jest wersjonowane w PostgreSQL. Etap: v1, po trzech integracjach MVP.

## 13. Alerty i powiadomienia

Bez zmian względem wersji 1.1 (sekcja 9): statusy, przypisanie, komentarze, powody zamknięcia, transactional outbox, ochrona przed SSRF. Kanały w MVP: webhook, Discord, e-mail. SMS i eskalacje w v1.

Nowe alerty systemowe:

- utrata heartbeatu / przerwa w źródle / próba deinstalacji agenta;
- zmiana polityki archiwum NIS2 i błąd weryfikacji integralności;
- przepełnienie kwarantanny, wzrost liczby nieznanych logów;
- zaleganie odbiorców strumienia ponad próg.

## 14. Bezpieczeństwo SIEM

Wszystkie punkty z wersji 1.1 (sekcja 10) pozostają. Dodatkowo:

- tokeny deinstalacji per agent, generowane wyłącznie przez rolę administratora, z audytem;
- operacje na archiwum NIS2 (wyłączenie, skrócenie retencji, eksport) wymagają ponownego uwierzytelnienia;
- dekodery i reguły to dane bez wykonywalnego kodu, z limitami kosztu;
- sekrety konektorów API w magazynie sekretów, rotacja, brak zwracania do przeglądarki.

## 15. Stos technologiczny

| Element | Wybór | Uwagi |
|---|---|---|
| Agent, endpoint przyjmujący, normalizator, detekcja | Go | Jeden język rdzenia |
| Konektory API, narzędzia, dane testowe | Python (lub Go) | Osobne procesy przez ten sam endpoint |
| Trwały strumień | NATS JetStream | Retencja według najwolniejszego odbiorcy |
| Magazyn zdarzeń | **ClickHouse** (decyzja podjęta) | Kolumnowy, wysoka kompresja, szybkie agregacje, SQL, TTL; słabsze wyszukiwanie pełnotekstowe i brak gotowego UI |
| Konfiguracja, alerty, stan reguł, manifesty | PostgreSQL | Outbox, wersje |
| Archiwum | Laboratorium: dysk lokalny + łańcuch hashy (zmiana 1.6: MinIO nie publikuje już obrazów); później S3 z Object Lock w trybie compliance | W produkcji dowolny magazyn S3 z blokadą (AWS, Wasabi, Backblaze, firmowy) |
| Panel | React + TypeScript | Do czasu etapu 5 przeglądanie zdarzeń przez Grafanę z wtyczką ClickHouse |
| Monitoring | Prometheus + Grafana | Poza samym SIEM |

**OpenSearch vs ClickHouse:** wybrany ClickHouse. Uzasadnienie: docelowe 5 000–15 000 EPS (setki GB dziennie) — kolumnowa kompresja i agregacje (progi, `count distinct`) są kluczowe dla detekcji w profilu pełnym i dla wyszukiwania na dużych zakresach. Dostęp do magazynu odbywa się przez warstwę abstrakcji (interfejs zapisu i zapytań).

### 15a. Model danych w ClickHouse

- **Tabela zdarzeń** `events` (MergeTree): stałe kolumny dla rdzenia ECS (`timestamp`, `event_id`, `event_dataset`, `event_code`, `event_action`, `event_outcome`, `host_name`, `host_id`, `agent_id`, `user_name`, `user_domain`, `source_ip`, `destination_ip`, `process_*` …) z właściwymi typami (`DateTime64`, `IPv6`/`IPv4`, `LowCardinality(String)`).
- **Pola zmienne** z dekoderów: kolumna `fields Map(LowCardinality(String), String)` (lub typ JSON, jeśli okaże się stabilny w wybranej wersji). Pola często używane w regułach można „awansować” do stałych kolumn bez zmiany reguł (warstwa abstrakcji mapuje nazwę pola ECS na kolumnę lub klucz mapy).
- **Oryginał** w kolumnie `raw String CODEC(ZSTD)` — wysoka kompresja, nieindeksowany.
- **Partycjonowanie** po dniu, **`ORDER BY (event_dataset, host_id, timestamp)`** — dobór klucza sortowania do zweryfikowania na typowych zapytaniach.
- **Retencja:** `TTL timestamp + INTERVAL 5 DAY` (wartość z konfiguracji).
- **Wyszukiwanie tekstowe:** indeksy pomijające (`tokenbf_v1` / `ngrambf_v1`) na `raw` i `message`; pełnotekstowe indeksy nowszych wersji ClickHouse do oceny. Wyszukiwanie zawsze z zakresem czasu.
- **Duplikaty:** dostarczanie co najmniej raz może zapisać to samo zdarzenie dwa razy. Deduplikacja przed zapisem po `event_id` (okno w zapisującym procesie) + `ReplacingMergeTree` jako zabezpieczenie; deduplikacja w ClickHouse jest odroczona (przy scalaniu), więc detekcja nie może na niej polegać.
- **Zapis:** wyłącznie paczkami (np. 10–50 tys. wierszy lub co 1–2 s) przez własny proces czytający z NATS — potwierdzenie wiadomości w NATS dopiero po udanym `INSERT`. Bez wbudowanego silnika tabel NATS, aby zachować kontrolę nad potwierdzeniami.
- **Alerty** pozostają w PostgreSQL (źródło prawdy); tabela `alerts` w ClickHouse opcjonalnie jako projekcja do analiz.
- **Detekcja `index_query`:** reguły kompilowane do SQL, z checkpointem i zakładką czasową jak w wersji 1.1.

## 16. Laboratorium

| Element | Cel |
|---|---|
| Kontroler domeny (Windows Server) + 2–3 stacje Windows 10/11 | AD, polityki audytu, Sysmon, agent |
| Serwer Windows z IIS (opcjonalnie Kentico) | Logi W3C, dekoder plików |
| Host Linux | Serwer SIEM w kontenerach, później agent Linux |
| FortiGate-VM (wersja ewaluacyjna) lub generator logów FortiGate | Syslog key=value, tryb kolektora |
| Testowy tenant Entra ID/M365 (z licencją lub trialem P1/P2) | Konektor API |
| Atomic Red Team / własne skrypty ataków | Weryfikacja scenariuszy detekcji |
| Publiczne zbiory danych (np. próbki EVTX z atakami, OTRF Security-Datasets) | Testy reguł i dekoderów bez dostępu do danych firmy |
| **Generator obciążenia w Go** | Symulacja 3500 agentów, 5 000–15 000 EPS, bursty, rozłączenia |
| Elastic Security (lokalnie) | Porównanie wyników detekcji na tych samych danych |

Żadne logi z firmy nie trafiają do laboratorium bez zgody firmy i anonimizacji.

## 17. Etapy

Szacunki w godzinach pracy. Przy ok. 12 h tygodniowo: **40 h ≈ 1 miesiąc**. To budżet planistyczny z dużą niepewnością, uwzględniający naukę Go w trakcie.

| Etap | Godziny | Rezultat | Warunek ukończenia |
|---|---|---|---|
| **0. Fundamenty** | 30–50 | Laboratorium AD, repozytorium, CI, kontrakt paczki i ID (załącznik A), schemat zdarzenia v1, polityka audytu wg załącznika B | Zdarzenie 4624 z DC ma opisaną drogę i docelowy kształt ECS |
| **1. Szkielet end-to-end** | 80–120 | Prosty agent Windows (Event Log + bookmark) → mTLS → JetStream → normalizator → ClickHouse, przeglądanie w Grafanie | Zdarzenie z DC widoczne w wyszukiwarce i śledzone po stałym ID |
| **2. Niezawodny agent** | 100–150 | Bufor offline, rejestracja tokenem, certyfikaty, heartbeat, konfiguracja z serwera, usługa, MSI | Restart, brak sieci przez 30 min i rotacja nie powodują luk; instalacja MSI w trybie cichym działa |
| **3. Archiwum NIS2** | 50–80 | Archiwizator, dysk lokalny (później S3 z Object Lock), łańcuch hashy, weryfikacja, konfiguracja `raw_archive` | Usunięcie lub podmiana paczki wykrywana przez weryfikację; replay z archiwum działa |
| **4. Detekcja – podstawy** | 100–150 | Kompilator Sigma, pojedyncze zdarzenia i progi w **obu** silnikach, testy zgodności, alerty w PostgreSQL, outbox, Discord/webhook | Scenariusze z sekcji 11 (Windows) wykryte w obu profilach; restart i replay nie dublują alertów |
| **5. Panel MVP** | 150–250 | Alerty (triage), reguły (wersje, test), agenci (status, grupy, tokeny deinstalacji), przełącznik archiwum, profile, RBAC, audyt | Pełny scenariusz: atak w labie → alert → powiadomienie → analiza → zamknięcie |
| **6. Kolektor syslog + dekodery** | 100–150 | Tryb kolektora w agencie, dekoder FortiGate, edytor dekoderów (JSON, kv, CSV/W3C), kwarantanna z ponownym przetwarzaniem | Logi FortiGate i IIS znormalizowane; nowy dekoder utworzony w panelu przechodzi test na próbce |
| **7. Entra/M365 + korelacja** | 80–120 | Konektor API z kursorem, mapowanie tożsamości, pierwsze reguły międzyźródłowe | Password spraying wykryty łącznie z AD i Entra; logowanie VPN i Entra powiązane z tą samą osobą |
| **8. Ochrona agenta + skala** | 100–150 | Zabezpieczenie usługi, token deinstalacji, alerty sabotażu; test obciążenia generatorem | Próba zatrzymania lub deinstalacji wykryta; 24 h przy docelowym EPS bez narastającego zalegania |
| **Razem do MVP** | **790–1220** | | **ok. 20–30 miesięcy przy 12 h/tydz.** |

**Stan i zmiana kolejności (aktualizacja 1.3):**

- Etap 1 **ukończony**: agent Windows → mTLS → NATS JetStream → normalizator → ClickHouse → Grafana, na VM w Proxmoxie.
- Z etapów 2 i 8 zrobione wcześniej: usługa z restartem po awarii, limity zasobów, diagnostyka (`status`, Podgląd zdarzeń), ochrona plików agenta, kopia stanu w rejestrze, instalator `vardr-agent install` z PATH i poleceniami `start/stop/status/test/set-server`.
- Nowa kolejność: **etap 2 + część etapu 5 (panel: logowanie, agenci, wdrażanie tokenem, wyszukiwarka zdarzeń)** → etap 3 (archiwum NIS2) → etap 4 (detekcja) → reszta etapu 5 (alerty, reguły) → etapy 6–8. Uzasadnienie: bez zarządzania agentami (rejestracja, heartbeat, konfiguracja z serwera) wdrożenie detekcji na więcej niż kilka maszyn jest niepraktyczne.
- **Proponowany etap 1.5 – wzmocnienie (40–60 h, przed panelem):** kolejka bez cichych strat i limit przyjmowania w ingest (K1), odporność writera na wadliwe wiersze (K2), generator obciążenia i metryki z pulpitem „zdrowie potoku” (K4), równoległy normalizator, rozrzut ponowień w agencie i krótsza retencja surowego XML (W1–W3), zalecenia GPO dla rozmiaru dzienników i ostrzeżenie w agencie (K3), testy w GitHub Actions (M1). Szczegóły: załącznik E.
- **Etap 1.5 – postęp:** **etap 1.5 zakończony** (06–07.10.2026): K1, K2, K3, K4, W1, W2 (mechanizm), W3 i M1. K1, K3, K4, W1 i W2 sprawdzone na żywo, K2 i W3 testami jednostkowymi. Potok nadąża przy 10 000 zdarzeń/s na VM z 4 vCPU. Opcjonalnie później: wydajność writera (W7).
- **Etap 2 + panel – postęp:** moduł 1 (logowanie i role) gotowy 07.10.2026: siem-api, baza Saga (PostgreSQL) z migracjami, konta, sesje, audyt, aplikacja React z Mantine pod HTTPS :8444. Moduł 2 (Huginn: heartbeat agentów, lista i szczegóły agenta) gotowy 07.10.2026, sprawdzony na 1000 symulowanych agentach. Moduł 3 (Bifröst: tokeny rejestracyjne, paczka bez klucza prywatnego, CA agentów, automatyczne odnawianie i unieważnianie certyfikatów, `vardr-agent upgrade`) gotowy 07.10.2026. Moduł 4 (Mímir: wyszukiwarka zdarzeń z językiem zapytań, histogramem, szczegółami i surowym XML; konto ClickHouse tylko do odczytu) gotowy 07.10.2026. Konfiguracja agentów z serwera (grupy z profilem i limitami, agent 0.5.0 pobiera ją co 5 min i stosuje bez restartu) gotowa 07.10.2026 – **moduły 1–4 panelu zakończone**; agent 0.6 (08.10.2026): bufor dyskowy z limitem i polityką przepełnienia, pomiar zegara, instalator MSI – **etap 2 zakończony** po teście na stacjach laboratorium AD. Dalej: etap 3 (archiwum NIS2, Urd) i etap 4 (detekcja, Gjallarhorn).
- **Etap 3 – postęp:** część 1 (archiwizator Urd) gotowa 07.10.2026: segmenty na dysku, godzinowe manifesty z łańcuchem hashy w Sadze, weryfikacja integralności co 6 h, retencja 30 dni, metryki, polecenia `verify` i `disable`. Sprawdzone na VM (2427/2427 paczek testu obciążenia w archiwum). Część 2 (moduł Urd w panelu: stan zgodności, łańcuch manifestów, historia weryfikacji, weryfikacja na żądanie z audytem) gotowa 07.10.2026; alert przy niezgodności dojdzie z modułem alertów (etap 4). Po przeglądzie (07.10.2026) wzmocnienie archiwum: osobne role bazy, ochrona dysku i osobny dysk 150 GB, weryfikacja z budżetem, kopie zapasowe, alerty w Grafanie, skrypt wdrożenia. Część 3a (eksport dla audytora: paczka z segmentami, łańcuchem i kotwicą, `check-export`, audyt zlecenia i pobrania) gotowa 07.10.2026. Część 3b (replay: osobna ścieżka NATS, kopie normalizatora i writera, tabela siem.events_replay, przełącznik w Mímirze) gotowa 07.10.2026 – sprawdzone: 100 117 zdarzeń odtworzonych zgodnie z siem.events. Część 4 (polityka w panelu: włączenie, retencja w granicach z konfiguracji serwera, wyłączanie grup i agentów; osłabienie tylko z ponownym podaniem hasła, z karencją 24 h, alertem i możliwością anulowania; źródła bez archiwizacji; eksport z filtrem źródeł) gotowa 07.10.2026 – **etap 3 zakończony**. Uproszczenie: jedna retencja dla całego archiwum (segmenty mieszają źródła); osobna retencja per źródło – po MVP. Dalej: etap 4 (detekcja, Gjallarhorn).
- **Etap 5 – postęp:** praca z alertami (filtry, przypisanie, oś czasu z notatkami, akcje zbiorcze, powiązane alerty), burza alertów (limit na regułę i wiadomości zbiorcze), reguły w panelu (wersje, włączanie z hasłem, test na zdarzeniach z alertami, które by powstały), stan systemu (Himinbjörg) i filtry powiadomień na kanałach – gotowe 09.10.2026; scenariusz atak → alert → powiadomienie → analiza → zamknięcie przeprowadzony w laboratorium AD – **etap 5 zakończony**. Tokeny deinstalacji przesunięte do etapu 8.
- **Etap 4 – postęp:** część 4a (kompilator podzbioru Sigmy w Go, rozszerzenia Vardra, pierwsze reguły w `rules/`) i 4b (siem-detector – silnik w locie, alerty w Sadze z deduplikacją i łączeniem trafień, outbox → kanały powiadomień, moduł Gjallarhorn w panelu) gotowe 09.10.2026; sprawdzone w laboratorium AD (PowerShell -EncodedCommand, podejrzany skrypt, usługa z katalogu użytkownika, dodanie do Backup Operators, nowe konto). Część 4c (progi `count` / `count distinct` w oknie, stan progów w Sadze odporny na restart, reguły brute force i password spraying) gotowa 09.10.2026 i sprawdzona w laboratorium. Część 4d (silnik zapytań na ClickHouse, wspólna semantyka progów, test zgodności obu silników w CI) gotowa 09.10.2026 i sprawdzona w laboratorium. Część 4e (utrata łączności z agentem z progiem w grupie, czyszczenie dzienników 1102/104, zatrzymanie usług bezpieczeństwa; scenariusze sprawdzone w laboratorium AD) gotowa 09.10.2026 – **etap 4 zakończony** (scenariusze FortiGate i Entra ID czekają na integracje).

**Kamienie milowe po drodze:**

- po etapie 1 (ok. 3–4 miesiące): logi Windows widoczne w wyszukiwarce;
- po etapie 4 (ok. 9–14 miesięcy): działająca detekcja w obu profilach i archiwum NIS2. To pierwsza wersja, którą da się sensownie pokazać;
- po etapie 5: używalny produkt z własnym panelem.

**Po MVP (v1/v2)** – zaktualizowane w sekcji 17a: agent Linux, SentinelOne, F5, Forcepoint, GreyCortex, Kentico, sekwencje i korelacje zaawansowane, edytor regex/grok, SMS i eskalacje, MFA przez dostawcę tożsamości, polityki per `event.dataset`, aktualizacje agentów, HA.

**Sposoby skrócenia ścieżki, jeśli zajdzie potrzeba:**

- w etapie 1 jako tymczasowy agent użyć gotowego kolektora (Vector, Fluent Bit) z tym samym kontraktem endpointu;
- etap 5 ograniczyć do alertów i agentów, a reguły edytować jako pliki w repozytorium;
- etap 8 (test skali) przesunąć za etap 4, jeśli wyniki etapu 0 sugerują problemy wydajnościowe.

## 17a. Plan wersji po 1.0 (26.10.2026)

MVP zamknięte 17.10.2026 (etapy 0–8), wydane wersje 1.0.1 (English update) i 1.0.2 (poprawki CodeQL). Kolejne funkcje wychodzą jako osobne wydania, w tej kolejności. Szacunki w godzinach pracy, jak w sekcji 17.

| Wersja | Funkcja | Godziny | Zależy od |
|---|---|---|---|
| **1.1** | API dla integracji – ✅ wydane w 1.2.0 (26.10.2026) | 30–40 | – |
| **1.2** | Powiadomienia Power Automate / Microsoft Teams – ✅ wydane w 1.2.0 (26.10.2026) | 15–20 | – (podpis HMAC wspólny z webhookiem) |
| **1.3** | Scoring ryzyka osób i stacji – ✅ wydane w 1.3.0 (26.10.2026) | 40–60 | mapowanie tożsamości (etap 7) |
| **1.4** | Serwer MCP (AI tylko do odczytu) – ✅ wydane w 1.4.0 (26.10.2026) | 30–40 | 1.1 |
| **1.5** | Asystent AI w panelu (eksperymentalny) – ✅ wydane w 1.5.0–1.5.3 (27.10.2026): analiza alertu i incydentu, czat, korelacja alertów, dokumentacja, propozycje pól zgłoszenia NIS2, wyjątki reguł z propozycjami AI, propozycje reguł w trybie próbnym | 60–80 | 1.1, 1.4; korzysta z 1.3 |

### 1.1 – API dla integracji

Panel już korzysta z `/api/v1`; brakuje dostępu dla programów.

- **Konta serwisowe z tokenami:** token przypisany do profilu uprawnień (`panel/internal/perm`), z datą wygaśnięcia, unieważnianiem i datą ostatniego użycia; w bazie tylko skrót tokenu, pełny token pokazany raz przy utworzeniu.
- **Bezpieczeństwo:** limit zapytań na token, każda zmiana wykonana tokenem w audycie (z nazwą konta serwisowego), operacje wymagające ponownego podania hasła niedostępne dla tokenów.
- **Dokumentacja OpenAPI** generowana z kodu lub utrzymywana obok, publikowana z panelem.
- **Warunek ukończenia:** skrypt z tokenem tylko do odczytu pobiera alerty i zdarzenia; próba zmiany kończy się 403 i wpisem w audycie.

### 1.2 – Power Automate i Microsoft Teams

Microsoft wycofuje webhooki Teams oparte na connectorach Office 365; następcą są przepływy *Workflows* (Power Automate) z wyzwalaczem HTTP. Jeden kanał obsługuje oba przypadki.

- Nowy typ kanału powiadomień: **Power Automate / Teams** – wiadomość jako *Adaptive Card* (waga, reguła, komputer, osoba, przycisk „Otwórz w panelu”), te same zdarzenia i filtry co Discord (alerty, rozwiązania, podsumowania, incydenty, terminy NIS2, kotwica archiwum), w języku systemu.
- **Podpis HMAC** wiadomości (także dla ogólnego webhooka) – odbiorca może sprawdzić, że wiadomość wysłał Vardr. *Uwaga z realizacji (26.10.2026): Power Automate nie ma wbudowanej funkcji HMAC – przy Teams nadawcę uwierzytelnia tajny adres przepływu (`sig=…`), a podpis sprawdza usługa, do której przepływ przekazuje wiadomość (np. Azure Function), albo odbiorca webhooka.*
- Dokumentacja: gotowy przepływ „wiadomość na kanale Teams” i przykład automatyzacji (np. zgłoszenie w systemie ticketów).
- **Warunek ukończenia:** alert z laboratorium widoczny jako karta na kanale Teams; wiadomość z błędnym podpisem odrzucona przez odbiorcę sprawdzającego podpis (test jednostkowy podpisu; Power Automate – patrz uwaga wyżej).

### 1.3 – Scoring ryzyka osób i stacji

Ryzyko oparte na alertach: wiele drobnych alertów, z których żaden osobno nie jest groźny, razem daje sygnał.

- **Na osobie** (`user.identity` – AD, Entra ID i VPN razem), nie na koncie, oraz na stacji (`host.name`).
- **Punkty** za alert według wagi (domyślnie: niski 1, średni 5, wysoki 15, krytyczny 40), **wygaszanie w czasie** (np. połowa po 14 dniach), **mnożniki** dla kont uprzywilejowanych i stacji krytycznych (np. grupa DC). Alerty zamknięte jako fałszywy alarm się nie liczą.
- **Poziomy:** niski, średni, wysoki, krytyczny – progi ustawiane w panelu. Wejście osoby lub stacji w poziom krytyczny tworzy alert.
- **Panel:** ranking osób i stacji, wynik i jego składniki (które alerty, ile punktów) w alercie, incydencie, Huginnie i Tożsamościach.
- Później: reguły „tylko punkty” (dodają ryzyko bez alertu).
- **RODO:** ranking ryzyka pracowników to profilowanie – w dokumentacji zalecenie uzgodnienia z IOD; wgląd w wyniki jako osobne uprawnienie w profilach.
- **Warunek ukończenia:** seria alertów niskich i średnich jednej osoby z AD i Entra ID podnosi ją do poziomu krytycznego i tworzy alert; po zamknięciu alertów jako FP wynik spada.

### 1.4 – Serwer MCP

Serwer [Model Context Protocol](https://modelcontextprotocol.io) pozwala podłączyć do Vardra dowolnego klienta AI – lokalny model (Ollama, LM Studio) albo zewnętrzny (np. Claude Desktop).

- Narzędzia **tylko do odczytu**: wyszukiwanie zdarzeń (język Mímira, obowiązkowy zakres czasu i limit wierszy), alerty, oś czasu incydentu, reguły, pokrycie ATT&CK, stan agentów i źródeł, scoring ryzyka (1.3).
- Dostęp tokenem z 1.1 z własnym profilem uprawnień; każde wywołanie narzędzia w audycie (kto, co, ile danych).
- **Zastosowania:** czego brakuje (luki ATT&CK zestawione z posiadanymi źródłami), wgląd w incydent, kolejne zapytania, powtarzalne fałszywe alarmy jako kandydaci na wyjątki.
- **Warunek ukończenia:** lokalny model odpowiada na pytanie „co się działo na koncie X w ostatnich 24 h” danymi z Vardra; token bez uprawnienia do zdarzeń dostaje odmowę.

### 1.5 – Asystent AI w panelu (eksperymentalny)

- Przycisk „Analiza AI” przy alercie i incydencie: streszczenie, możliwe wyjaśnienia, proponowane zapytania (do uruchomienia jednym kliknięciem), mapowanie na ATT&CK, szkic zgłoszenia NIS2.
- Wsparcie wykrywania wzorców: grupowanie podobnych alertów, propozycje wyjątków dla powtarzalnych FP, propozycje reguł dla luk w pokryciu – zawsze do zatwierdzenia przez człowieka.
- Połączenie z endpointem zgodnym z OpenAI (lokalnym albo zewnętrznym), ustawiane przez administratora; domyślnie wyłączone.
- **Zasady (obowiązują też 1.4):**
  - **AI tylko podpowiada** – nie zamyka alertów, nie zmienia reguł ani ustawień. Pola zdarzeń (nazwy kont, linie poleceń, treść sysloga) kontroluje atakujący, więc mogą zawierać instrukcje dla modelu (prompt injection); dane z logów są przekazywane modelowi jako dane, a odpowiedź jest wyraźnie oznaczona jako sugestia.
  - **Dane osobowe:** domyślnie tylko model lokalny; zewnętrzny – świadome włączenie przez administratora (wpis w audycie), z opcją maskowania kont, adresów i nazw komputerów.
  - **Audyt** każdego zapytania: kto pytał, o co, jakie dane wysłano i do jakiego modelu; limit zapytań.

### Backlog (bez ustalonej kolejności)

- **Źródła:** agent Linux; SentinelOne, F5, Forcepoint, GreyCortex, Kentico; pliki IIS/W3C; syslog po TLS z uwierzytelnieniem; logowania nieinteraktywne Entra ID (API beta, przy prawdziwym tenancie).
- **Detekcja:** sekwencje i korelacje zaawansowane; edytor dekoderów regex/grok.
- **Powiadomienia:** SMS i eskalacje (częściowo możliwe już przez Power Automate z 1.2).
- **Logowanie:** SSO / MFA przez dostawcę tożsamości (Entra ID), WebAuthn.
- **Archiwum:** S3 z Object Lock (compliance); retencja i polityki per `event.dataset`.
- **Agenci:** automatyczne aktualizacje.
- **Skala i dostępność:** HA i replikacja (W6), wydajność writera (W7), częste pola z `fields` w osobnych kolumnach (M4).
- **Porządki z przeglądu:** kwarantanna nieczytelnych wiadomości w normalizatorze (M2), zapora na serwerze i ograniczenie dostępu do Grafany i ingest (M5), raport synchronizacji czasu agenta (M6) – do sprawdzenia, które są nadal aktualne.
- **Podpisywanie programów Windows (Authenticode):** `vardr-agent.exe`, MSI, `odczytaj.exe`, `vardr-mcp.exe` – niepodpisany, nowy plik pobrany z przeglądarki Microsoft Defender blokuje heurystyką reputacji (np. `Wacatac.C!ml` dla `vardr-mcp.exe`, 26.10.2026). Certyfikat do podpisywania kodu (np. Azure Trusted Signing) – decyzja i koszt po stronie właściciela projektu.
- **Publikacja:** automatyczne wydania na GitHubie (Actions na tagu: paczka serwera, MSI agenta, `odczytaj.exe`), szybki start w README.
- **Laboratorium:** krótsza retencja surowego XML w ClickHouse (np. 1 dzień zamiast 5 – archiwum Urd przechowuje oryginały).

## 17b. Plan wersji 1.6 (27.10.2026)

Po zamknięciu planu 17a (1.1–1.5) – etap 1.6: Vardr gotowy do instalacji poza laboratorium. Wydania 1.6.x w tej kolejności:

**Stan:** wszystkie punkty planu wydane razem jako **1.6.0** (27.10.2026).

| Wersja | Funkcja | Godziny | Uwagi |
|---|---|---|---|
| **1.6.0** | Publikacja i podpisywanie: wydania na GitHubie z tagu, podpis Authenticode programów Windows | 6–10 | podpis – po założeniu konta Azure Artifact Signing (decyzja i koszt właściciela) |
| **1.6.1** | Logowanie do panelu przez Entra ID (SSO, OIDC) z MFA dostawcy | 20–30 | konto lokalne administratora zostaje jako awaryjne |
| **1.6.2** | Nowe źródła syslog: Linux (rsyslog), pfSense/OPNsense, Cisco ASA (wybrane 27.10.2026 zamiast agenta Linux) | 30 | agent Linux – później, jeśli syslog nie wystarczy |
| **1.6.x** | Porządki z przeglądu M2, M5, M6 – po sprawdzeniu, które są aktualne | 3 | M6 już zrobione (agent 0.6); M2 i M5 – 27.10.2026 |

### 1.6.0 – Publikacja i podpisywanie

- **Wydanie z tagu** (`.github/workflows/release.yml`): programy Windows budowane na Windows, paczka serwera na Linuksie z tymi samymi plikami, `SHA256SUMS`, opis z `CHANGELOG.md`; ponowne uruchomienie podmienia pliki.
- **Podpis Authenticode** przez Azure Artifact Signing (OIDC z GitHub Actions, bez sekretów certyfikatu w repozytorium), włączany zmienną `SIGNING=true`; bez niej wydanie powstaje bez podpisu.
- **Szybki start w README** – pobranie paczki z wydania i sprawdzenie sumy.
- **Warunek ukończenia:** tag tworzy wydanie z paczką, programami i sumami; po włączeniu podpisu `Get-AuthenticodeSignature vardr-mcp.exe` zwraca `Valid`, a pobranie z przeglądarki nie jest blokowane.

### 1.6.1 – Logowanie przez Entra ID

Stan: napisane (27.10.2026), do sprawdzenia na prawdziwej dzierżawie Entra ID przed wydaniem.

- OIDC (authorization code + PKCE, bez zewnętrznych bibliotek) z aplikacją w Entra ID; konto panelu wiązane z użytkownikiem Entra ID (`oid`), profil uprawnień z grup Entra ID (powiązania grupa → profil w kolejności, przy każdym logowaniu).
- MFA i polityki dostępu warunkowego po stronie Entra ID; polityka MFA panelu wymaga `amr` = `mfa` w tokenie; lokalne MFA panelu zostaje dla kont lokalnych.
- Konta SSO bez hasła w panelu: operacje chronione hasłem potwierdzane ponownym logowaniem w Entra ID (okienko, ważne 5 minut w sesji).
- Konto lokalne administratora jako awaryjne (break-glass), w audycie.
- **Warunek ukończenia:** analityk loguje się kontem Entra ID z MFA, dostaje profil z grupy; wyłączenie konta w Entra ID blokuje kolejne logowanie.

### 1.6.2 – Nowe źródła syslog

Stan: napisane i sprawdzone w laboratorium (27.10.2026) – rsyslog z VM: zdarzenia `linux.auth` i alerty (seria SSH, nieistniejące konta, nowe konto, grupa sudo).

- Dekodery wbudowane: `linux` (sshd, sudo, su, PAM, shadow-utils), `pfsense` (filterlog, logowania do panelu; także OPNsense), `cisco-asa` (listy dostępu, logowania, AAA, AnyConnect, polecenia).
- Produkty Sigmy `linux`, `pfsense`/`opnsense`, `cisco`/`asa`; 11 reguł; logowania z nowych źródeł w tabeli logowań i korelacjach (widok odświeżany przez instalator przy aktualizacji).
- **Warunek ukończenia:** próbki i korpus zgodności silników przechodzą; prawdziwy serwer Linux przez rsyslog w laboratorium daje zdarzenia `linux.auth` i alert przy serii nieudanych logowań SSH.

## 18. Pierwsze kroki (etap 0)

1. Postawić laboratorium: DC + 1 stacja Windows, polityka audytu (logowania, zarządzanie kontami, grupami, procesy), Sysmon z gotową konfiguracją bazową.
2. Wyeksportować próbkę zdarzeń (4624, 4625, 4688, 4720, 4728, 1102, Sysmon 1/3) i opisać ich mapowanie na ECS.
3. Kontrakt paczki: ustalony w załączniku A; w etapie 0 zamienić go na schemat JSON i testy kontraktowe.
4. Utworzyć repozytorium (monorepo Go: `agent/`, `server/ingest`, `server/normalizer`, `server/detection`, `server/archiver`, `pkg/schema`, `deploy/compose`), CI z testami i lintem.
5. `docker compose`: NATS JetStream, ClickHouse, Grafana (wtyczka ClickHouse), PostgreSQL.
6. Prosty skrypt PKI: CA laboratoryjne, certyfikat serwera, certyfikat testowego agenta.
7. Zapisać podjęte decyzje (ClickHouse, kontrakt paczki, retencje) jako ADR w repozytorium.
8. Licznik zdarzeń wysłanych, przyjętych i zapisanych od pierwszego dnia.

## 19. Testy i bramki jakości

Wszystkie testy z wersji 1.1 (sekcja 12) pozostają. Dodatkowo:

| Test | Oczekiwany wynik |
|---|---|
| Zgodność silników | Ta sama reguła na tym samym zbiorze daje ten sam logiczny alert w `stream` i `index_query` |
| Integralność archiwum | Usunięcie, podmiana lub zmiana kolejności paczki wykryte przez weryfikację |
| Wyłączenie archiwum | Wymaga ponownego uwierzytelnienia, tworzy wpis audytu i alert; dane historyczne nienaruszone |
| Zmiana profilu | Przejście wydajnościowy → pełny z re-indeksacją z archiwum bez duplikatów |
| Zatrzymanie / deinstalacja agenta | Bez tokenu deinstalacja się nie udaje; zatrzymanie usługi wykryte po stronie serwera |
| Przepełnienie Event Logu w trakcie przerwy sieci | Zdarzenia zachowane w buforze dyskowym albo jawny licznik strat |
| Dekoder z panelu | Test na próbce pokazuje poprawny wynik dopasowania; złośliwy regex nie blokuje normalizatora |
| Kolektor syslog | Przerwa łączności kolektor–serwer nie gubi logów z urządzeń w granicach bufora |
| Konektor API | 429/5xx, wygaśnięcie sekretu i opóźnione logi dostawcy obsłużone bez luk w kursorze |
| Skala | 3500 symulowanych agentów, docelowe EPS przez 24 h, uzgodniony burst, masowe ponowne połączenie po awarii serwera |

## 20. Ryzyka i otwarte decyzje

| Ryzyko / decyzja | Wpływ | Działanie |
|---|---|---|
| Czas: projekt po godzinach, 1 osoba | Utrata tempa, porzucenie | Kamienie milowe z działającym rezultatem co 2–4 miesiące; ścieżki skrócenia z sekcji 17 |
| Dwa silniki detekcji | Rozjazd semantyki, podwójna praca | Ograniczony język MVP, budowa funkcjami, testy zgodności w CI |
| Koszt magazynu przy 5–15 tys. EPS | Sprzęt w profilu pełnym | ClickHouse, filtrowanie u źródła (załącznik B), archiwum zamiast pełnego magazynu |
| Wyszukiwanie tekstowe w ClickHouse | Wolniejszy threat hunting po dowolnym tekście | Indeksy pomijające, obowiązkowy zakres czasu, normalizacja kluczowych pól do kolumn |
| Brak gotowego UI dla ClickHouse | Brak wyszukiwarki przed etapem 5 | Grafana jako rozwiązanie tymczasowe, wyszukiwarka w panelu etapu 5 |
| Agent Windows (wevtapi, usługa, MSI) w Go | Krzywa nauki | Etap 1 z prostym agentem; w razie blokady tymczasowo gotowy kolektor |
| Dostęp do Entra/M365 z licencją | Brak danych do etapu 7 | Wcześnie zorganizować testowy tenant lub trial |
| Wymagania NIS2 dla retencji | Błędne wartości domyślne | Retencja konfigurowalna, wartości uzgadniane z audytorem |
| Dane osobowe w logach | Zgodność z RODO przy wdrożeniu | RBAC, retencja, audyt; uzgodnienie z IOD przed użyciem danych firmy |

**Decyzje etapu 0:** podjęte 06.10.2026, patrz tabela „Decyzje ustalone” na początku dokumentu.

## Załącznik A. Kontrakt paczki agent → serwer (v1)

**Transport:** `HTTPS POST /v1/ingest`, TLS 1.3 z mTLS (certyfikat agenta), nagłówek `Content-Encoding: gzip` lub `zstd`, `Content-Type: application/json`.

**Paczkowanie:** agent wysyła paczkę po zebraniu limitu zdarzeń (domyślnie 500) albo po upływie czasu (domyślnie 2 s), w zależności co nastąpi pierwsze. Limit rozmiaru paczki po dekompresji: domyślnie 5 MiB.

**Treść paczki:**

```json
{
  "schema": "siem.batch.v1",
  "batch_id": "UUIDv7",
  "agent_id": "agt-...",
  "sent_at": "2026-10-06T14:03:12.481Z",
  "events": [
    {
      "id": "agt-...:Security:g1:1849302",
      "source": "wineventlog:Security",
      "read_at": "2026-10-06T14:03:11.902Z",
      "raw": "<Event xmlns=...>...</Event>"
    }
  ]
}
```

- `agent_id` w paczce służy tylko diagnostyce. Serwer ustala tożsamość agenta wyłącznie na podstawie certyfikatu i odrzuca paczki z niezgodnym `agent_id`.
- `id` zdarzenia = `{agent_id}:{kanał}:g{generacja}:{EventRecordID}`. Generacja rośnie, gdy agent wykryje reset numeracji dziennika (np. numer rekordu mniejszy niż w bookmarku po odtworzeniu dziennika). Dla plików: `{agent_id}:{ścieżka-hash}:g{generacja}:{offset}`.
- Agent wysyła **surowy log** (`raw`): dla Event Log XML, dla plików linię tekstu. Parsowanie i normalizacja odbywają się na serwerze.
- Ponowne wysłanie paczki używa tego samego `batch_id` i tych samych `id` zdarzeń. Serwer deduplikuje po `id`.

**Odpowiedzi serwera:**

| Kod | Znaczenie | Zachowanie agenta |
|---|---|---|
| `200` + `{"batch_id": "...", "status": "accepted"}` | Paczka trwale zapisana w kolejce | Przesunięcie bookmarka, usunięcie z bufora |
| `400` | Paczka niepoprawna | Bez ponawiania; paczka do lokalnej kwarantanny, licznik błędów |
| `401` / `403` | Certyfikat nieważny, unieważniony lub niezgodna tożsamość | Wstrzymanie wysyłki, ponowna próba rejestracji / zgłoszenie stanu |
| `413` | Paczka za duża | Podział paczki na mniejsze i ponowienie |
| `429` / `503` | Przeciążenie | Ponowienie po `Retry-After` lub z rosnącym opóźnieniem i losowym rozproszeniem |
| `5xx`, timeout, brak połączenia | Błąd przejściowy | Ponowienie z rosnącym opóźnieniem; dane pozostają w źródle / buforze |

## Załącznik B. Domyślna lista zdarzeń Windows

Agent zbiera tylko zdarzenia, które Windows faktycznie zapisuje: większość wymaga włączenia zaawansowanej polityki audytu przez GPO (dla 4688 także opcji „Include command line in process creation events”), a kanał Sysmon wymaga instalacji Sysmona z konfiguracją. Lista jest konfigurowalna z serwera per grupa agentów (stacje / serwery / kontrolery domeny).

| Kanał | Event ID | Opis | Grupy |
|---|---|---|---|
| Security | 4624, 4625, 4634, 4647, 4648 | Logowania udane i nieudane, wylogowania, logowanie jawnymi poświadczeniami | wszystkie |
| Security | 4672 | Logowanie z uprawnieniami specjalnymi | wszystkie |
| Security | 4688 | Utworzenie procesu (z linią poleceń) | wszystkie |
| Security | 4697, 4698, 4702 | Instalacja usługi, utworzenie i zmiana zadania harmonogramu | wszystkie |
| Security | 4719, 1102 | Zmiana polityki audytu, wyczyszczenie dziennika | wszystkie |
| Security | 4720, 4722–4726, 4738, 4740, 4767 | Cykl życia kont, zmiany, blokady i odblokowania | serwery, DC |
| Security | 4728, 4729, 4732, 4733, 4756, 4757 | Zmiany członkostwa w grupach | serwery, DC |
| Security | 4768, 4769, 4771, 4776 | Kerberos (TGT, TGS, błędy pre-auth), walidacja NTLM | DC |
| System | 7036, 7040, 7045 | Zmiana stanu usługi, zmiana typu uruchamiania, nowa usługa | wszystkie |
| Microsoft-Windows-PowerShell/Operational | 4104 | Script Block Logging | wszystkie |
| Microsoft-Windows-Sysmon/Operational | 1, 3, 11, 13, 22 | Procesy, połączenia sieciowe, pliki, rejestr, DNS | wszystkie (jeśli Sysmon zainstalowany) |

**Celowo pomijane domyślnie (szum):** 5156/5158 (połączenia filtrowane przez WFP), 4656/4658/4663 (uchwyty i dostęp do obiektów), 4662 na DC (dostęp do obiektów katalogu, włączany tylko pod konkretne detekcje, np. DCSync, z filtrem). Można je włączyć regułą per grupa.

## Załącznik C. Panel zarządzania i wdrażanie agentów

### Architektura

```
przeglądarka ──HTTPS──► siem-api (Go) ──► PostgreSQL  (użytkownicy, role, agenci, grupy, tokeny, reguły, alerty, audyt)
                             │        └──► ClickHouse  (wyszukiwanie zdarzeń)
agent ──mTLS──► siem-ingest  └──► rejestracja agentów, heartbeat, konfiguracja dla agentów
```

- Frontend: React + TypeScript, serwowany przez `siem-api`.
- Grafana pozostaje narzędziem do monitorowania potoku (kolejki, opóźnienia, zapis), nie konsolą analityka.

### Moduły w kolejności

| # | Moduł | Zakres |
|---|---|---|
| 1 | Logowanie i role | konta lokalne, role administrator / analityk / tylko odczyt, audyt zmian; później SSO (Entra ID) i MFA |
| 2 | Agenci | lista (online/offline z heartbeatu, wersja, host), szczegóły (zdalny odpowiednik `vardr-agent status`), grupy, profile zdarzeń, limity zasobów |
| 3 | Wdrażanie | tokeny rejestracyjne (jednorazowe lub czasowe, przypisane do grupy), pobranie instalatora (ZIP, później MSI budowane `wixl`), gotowe polecenie instalacji |
| 4 | Zdarzenia | wyszukiwarka po ClickHouse z filtrami, szczegóły zdarzenia (pola, surowy XML) |
| 5 | Alerty, reguły, dekodery, archiwum NIS2 | razem z etapami 3–4 |

### Rejestracja agenta tokenem

1. Administrator w panelu tworzy token dla grupy (np. „Stacje – księgowość”, profil `workstation`, ważny 7 dni lub N użyć).
2. Panel udostępnia instalator: program, adres serwera, certyfikat CA i token – **bez klucza prywatnego**.
3. `vardr-agent install -server <adres> -token <token>`: agent generuje klucz lokalnie (nigdy nie opuszcza komputera), wysyła prośbę o certyfikat (CSR) z tokenem przez TLS z weryfikacją CA.
4. Serwer sprawdza token, nadaje identyfikator agenta, podpisuje krótkoterminowy certyfikat, zapisuje agenta w grupie i zwraca konfigurację.
5. Dalej: heartbeat co ~60 s (stan, wersja, limity, błędy kanałów), automatyczne odnawianie certyfikatu, konfiguracja pobierana z serwera.
6. Ten sam token może posłużyć do wdrożenia masowego (GPO / Intune / SCCM) w ramach limitu użyć.

`siem-pki package` (paczka z kluczem prywatnym) pozostaje wyłącznie narzędziem laboratoryjnym.

## Załącznik D. Nazewnictwo – Vardr i jego świat

> Vǫrðr (Vardr) – w wierzeniach nordyckich duch-strażnik, który towarzyszy człowiekowi
> od narodzin, czuwa nad nim i bywa widziany, zanim nadejdzie to, co ważne.

Trudno o lepszy opis SIEM-a: cichy strażnik, który stale czuwa i daje znać, zanim stanie się
coś złego. System nazywa się **Vardr**, a jego części biorą imiona z tego samego świata.

Do października 2026 projekt nazywał się Heimdall. Nazwę zmieniono przed publikacją, bo w
branży bezpieczeństwa IT są już zarejestrowane bardzo podobne znaki towarowe (m.in. Heimdal®).
Część identyfikatorów technicznych zachowała dawną nazwę dla zgodności z istniejącymi danymi
(ścieżki `/srv/heimdall` w laboratorium, formaty archiwum Urd, ID wbudowanych reguł,
`uid` alertów Grafany); dawny klucz reguł `heimdall:` jest nadal czytany.

### Mapa świata

```
            Huginn (agent na komputerze)
               │   kruk Odyna – lata po świecie i donosi, co widział
               ▼
   ════════ Bifröst ════════  szyfrowany most (mTLS, endpoint przyjmujący)
               │
               ▼
          Ratatoskr  ─────────────────────────────►  Urd
   (kolejka zdarzeń)                             (archiwum NIS2:
               │                                  co zapisane, tego się nie zmienia)
               ▼
            Bragi        tłumaczy „języki” logów na jeden wspólny (normalizacja, dekodery)
               │
               ▼
          Verðandi       spisuje to, co dzieje się teraz (zapis zdarzeń)
               │
               ▼
            Mímir        studnia mądrości – baza zdarzeń
               │
      ┌────────┴─────────┐
      ▼                  ▼
 Gjallarhorn         Hliðskjálf      ◄──── Saga
 (detekcja,          (panel – tron       (pamięć: użytkownicy, agenci,
  alerty)             Odyna, z którego    reguły, alerty)
                      widać wszystkie
                      światy)
```

### Słownik nazw

| Komponent | Nazwa | Postać w mitologii | Nazwa techniczna (kod, katalogi) |
|---|---|---|---|
| Cały system | **Vardr** | duch-strażnik, który stale czuwa i ostrzega | repozytorium `vardr` |
| Agent | **Huginn** | kruk Odyna („myśl”), co dzień okrąża świat i wraca z wieściami | `vardr-agent`, `agent/` |
| Kanał agent → serwer (mTLS, ingest) | **Bifröst** | tęczowy most do Asgardu, którego strzeże Heimdall | `siem-ingest`, `server/internal/ingest` |
| Kolejka (NATS JetStream) | **Ratatoskr** | wiewiórka biegająca po Yggdrasilu z wiadomościami | `nats`, `server/internal/bus` |
| Normalizator i dekodery | **Bragi** | bóg poezji i słowa | `siem-normalizer`, `server/internal/normalize` |
| Zapis zdarzeń do bazy | **Verðandi** | norna teraźniejszości („to, co się staje”) | `siem-writer`, `server/internal/chwriter` |
| Baza zdarzeń (ClickHouse) | **Mímir** | studnia mądrości, za łyk z której Odyn oddał oko | `clickhouse`, baza `siem` |
| Archiwum NIS2 (WORM) | **Urd** | norna przeszłości i jej studnia – przeszłości nie da się zmienić | etap 3 |
| Detekcja i alerty | **Gjallarhorn** | róg Heimdalla, strażnika Bifröstu, ogłaszający nadejście zagrożenia | etap 4 |
| Panel | **Hliðskjálf** | tron Odyna, z którego widać wszystkie dziewięć światów | `siem-api` + frontend, katalog `panel/` (załącznik C) |
| Konfiguracja i stan (PostgreSQL) | **Saga** | bogini, z którą Odyn codziennie pije ze złotych pucharów (Grímnismál); imię wiąże się z opowieścią i pamięcią | `postgres` |
| Monitorowanie potoku (Grafana) | – | narzędzie zewnętrzne, bez nazwy z mitologii | `grafana` |

Wolne nazwy na przyszłość:
- **Muninn** – drugi kruk Odyna („pamięć”), np. agent Linux lub kolektor syslog;
- **Skuld** – norna przyszłości, np. analiza anomalii i UEBA;
- **Gungnir** – włócznia Odyna, która nigdy nie chybia, np. automatyczna reakcja;
- **Yggdrasil** – drzewo łączące światy, np. nazwa całego wdrożenia lub klastra HA.

### Zasady

1. **Nazwy z mitologii** stosujemy tam, gdzie widzi je człowiek:
   - panel i jego menu;
   - dokumentacja i diagramy;
   - nazwy usług i kontenerów;
   - tytuły pulpitów;
   - komunikaty w stylu „Bifröst: 3 agentów nie łączy się od 15 min”.
2. **Nazwy opisowe** zostają w kodzie i tam, gdzie liczy się czytelność przy diagnozie:
   - pakiety i katalogi Go;
   - kolumny i tabele bazy;
   - zmienne środowiskowe;
   - logi techniczne (`component=ingest`).
3. Przy pierwszym wystąpieniu w dokumentacji zawsze podajemy obie formy: „Bifröst (ingest)”.
4. **Polecenie agenta to `vardr-agent`** (do wersji 0.7.x: `siem_agent`; aktualizacja przepina usługę na nowy plik). To nazwa, którą wpisuje administrator, i powinna mówić sama za siebie.

### Plan zmiany nazw

Zmiany robimy przy okazji pracy w danym obszarze, a nie jednym dużym przemianowaniem.

| Kiedy | Co zmienić | Uwagi |
|---|---|---|
| Start panelu (załącznik C) | Tytuł i logo panelu: „Vardr”; sekcje menu: Huginn (agenci), Mímir (zdarzenia), Gjallarhorn (alerty), Bifröst (wdrażanie i łączność) | nowy kod – bez migracji |
| Start panelu | Usługi w `docker-compose.yml`: `ingest`→`bifrost`, `nats`→`ratatoskr`, `normalizer`→`bragi`, `writer`→`verdandi`, `clickhouse`→`mimir`, nowe `saga` (PostgreSQL) i `hlidskjalf` (API + frontend) | zmiana nazw hostów w zmiennych środowiskowych (`SIEM_NATS_URL`, `SIEM_CLICKHOUSE_ADDR`), datasource Grafany i certyfikatu serwera (`-hosts`) |
| Start panelu | Moduł Go `siem` → `vardr` (ścieżka importu) | jednorazowa zamiana w całym repozytorium |
| Start panelu | Pulpit Grafany: „Vardr – zdrowie potoku” zamiast przeglądu zdarzeń (przegląd zdarzeń przejmuje Hliðskjálf) | Grafana zostaje do monitorowania |
| Etap 3 | Archiwizator od razu jako **Urd** (usługa `urd`) | nowy komponent |
| Etap 4 | Silnik detekcji i powiadomień od razu jako **Gjallarhorn** | nowy komponent |
| Instalator MSI (etap 2) | Nazwa wyświetlana usługi: „Vardr Huginn (agent SIEM)”; nazwa usługi `SiemAgent` i źródło w Podglądzie zdarzeń **bez zmian** | zmiana nazwy usługi wymagałaby migracji na wszystkich komputerach – tylko jeśli będzie wyraźny powód |
| Bez zmian | Polecenie `vardr-agent`, baza ClickHouse `siem`, prefiks identyfikatorów `agt-`, ścieżki `C:\Program Files\SiemAgent` i `C:\ProgramData\SiemAgent` | stabilne nazwy techniczne – zmiana kosztuje migrację, nie daje wartości |

## Załącznik E. Skalowanie i przeciążenie

Wnioski z przeglądu systemu po ukończeniu etapu 1 (06.10.2026).

### Zasada skalowania

Każdy etap przetwarzania jest osobną usługą. Pod obciążeniem dokłada się kopie **tylko tego etapu, który jest wąskim gardłem**. W Wazuhu jeden worker robi wszystko naraz (odbiór, dekodowanie, reguły), więc skaluje się całe workery.

| Element | Jak skalować | Dlaczego |
|---|---|---|
| Ingest – Bifröst | **poziomo**: N kopii za load balancerem | bez stanu; każda kopia tylko zapisuje paczkę do kolejki |
| Normalizator – Bragi | **poziomo**: `docker compose up -d --scale normalizer=N` | kopie dzielą pracę z jednej kolejki (wspólny trwały konsument NATS) |
| Writer – Verðandi | **poziomo**: `--scale writer=N` | jak wyżej; duplikaty usuwa ClickHouse (ReplacingMergeTree) |
| Detekcja – Gjallarhorn (etap 4) | **poziomo** | ten sam wzorzec konsumenta kolejki |
| Kolejka NATS – Ratatoskr | **najpierw pionowo**, potem klaster 3 węzłów | jeden węzeł przyjmuje setki MB/s; klaster głównie dla odporności na awarię |
| Baza – Mímir (ClickHouse) | **najpierw pionowo** (CPU, RAM, dyski), potem shardy i repliki | jeden serwer przyjmuje zwykle setki tysięcy wierszy/s; wcześniej kończy się dysk |

**Zasada:** elementy bez stanu poziomo, elementy przechowujące dane najpierw pionowo.

**Sprawdzone (06.10.2026):** 3 normalizatory i 2 writery na VM laboratoryjnej, 24 zdarzenia testowe. Wszystkie zapisane, bez duplikatów. Dokładanie workerów działa bez zmian w kodzie.

**Load balancer dla ingestu** musi przekazywać połączenie TLS **bez rozszyfrowania** (TCP passthrough, np. HAProxy). Rozszyfrowanie na load balancerze odcięłoby certyfikat klienta, a więc tożsamość agenta. Agenci zachowują jeden adres (adres load balancera lub nazwa DNS).

### Obsługa przeciążenia: trzy warstwy

```
3500 agentów ──► [1] ingest: przyjmuje tylko tyle, ile zdąży trwale zapisać;
                      nadmiar → HTTP 429 „spróbuj za X s” (X losowe)
                 [2] kolejka NATS: wyrównuje skoki; workery nadrabiają we własnym tempie;
                      pełna kolejka → odmowa zapisu (ingest odpowiada 503), nigdy usuwanie danych
                 [3] agent: ponawia z losowym rozrzutem; niewysłane dane czekają
                      w dzienniku Windows (później także w buforze dyskowym)
```

Szczyt ruchu (poniedziałek o 8:00, powrót serwera po awarii, pierwsze wdrożenie z `start_at: oldest`) ma się kończyć **opóźnieniem, a nie utratą danych ani awarią serwera**.

**Kiedy dokładać workery:** gdy rośnie zaległość konsumentów w NATS (wiadomości czekające na normalizator lub writer) albo opóźnienie od wystąpienia zdarzenia do zapisu. Na początku ręcznie, później automatycznie na podstawie metryk.

### Pomiary i wyliczenia (06.10.2026)

| Element | Wartość | Przy 10 000 zdarzeń/s |
|---|---|---|
| Normalizacja (benchmark, jeden rdzeń Ryzen 5 7500F) | cała ścieżka paczki: 56 µs przed W1, **19,9 µs po W1** (parser XML 3,8 µs) | na VM do 17 000 zdarzeń/s na kopię (przed W1: 4500); przy 10 000/s ok. 0,8 rdzenia |
| Kolejka NATS (oba strumienie) | ok. 200 B na zdarzenie | przy retencji 48 h było to ok. 340 GB; po poprawce K1 kolejka trzyma tylko zaległości: 8 GB na strumień ≈ 2 h zatoru przy 10 000/s |
| ClickHouse | 55 B na zdarzenie (dane laboratoryjne, kompresja ok. 15×); surowy XML 52%, pola 28% miejsca | ok. 47 GB/dzień, ok. 235 GB przy 5 dniach; logi Security kompresują się gorzej |
| Dziennik Windows jako bufor agenta | System i Application 20 MB (domyślnie); Security domyślnie też 20 MB | stacja (2 zdarzenia/s) ok. 2 h zapasu, serwer (1000/s) ok. 15 s |
| Agent | ok. 23 µs CPU na zdarzenie, 22–26 MB pamięci roboczej | 1000 zdarzeń/s ≈ 2,3% jednego rdzenia |

### Niedociągnięcia wykryte w przeglądzie

**Krytyczne**

| # | Problem | Skutek | Poprawka |
|---|---|---|---|
| K1 | Strumienie NATS: `discard: old`, retencja czasowa, limit 20 GB | przy dłuższej awarii writera lub bazy kolejka usuwa najstarsze **nieprzetworzone** dane, a agenci mają już potwierdzenie – cicha utrata | retencja do potwierdzenia przez wszystkich odbiorców, limit rozmiaru z `discard: new` (ingest → 503), limit przyjmowania w ingest (429), alarm zaległości. **Zrobione 06.10.2026** |
| K2 | Writer ponawia całą paczkę po błędzie ClickHouse | jeden wadliwy wiersz (np. data poza zakresem przy zepsutym zegarze komputera) zatrzymuje zapis wszystkich agentów | dzielenie paczki do wykrycia wadliwego wiersza → kwarantanna; korekta dat spoza zakresu. **Zrobione 06.10.2026** |
| K3 | Dziennik Windows (domyślnie 20 MB) jest jedynym buforem agenta | przy przerwie w łączności dłuższej niż minuty (serwer) lub godziny (stacja) zdarzenia zostają nadpisane | GPO: Security 512 MB–1 GB na serwerach i DC; ostrzeżenie agenta o zbliżającym się nadpisaniu; bufor dyskowy (etap 2). **Ostrzeżenia i zalecenia GPO zrobione 07.10.2026**; bufor dyskowy nadal w etapie 2 |
| K4 | Brak testu obciążenia i metryk | nie wiadomo, gdzie system pęknie ani kiedy dokładać workery | generator ruchu symulujący tysiące agentów, metryki Prometheus, pulpit „zdrowie potoku”. **Zrobione 06–07.10.2026** |

**Ważne**

| # | Problem | Poprawka |
|---|---|---|
| W1 | Normalizator przetwarza sekwencyjnie w jednym wątku i jest kosztowny (pomiar K4: ok. 4500 zdarzeń/s na kopię, 1,1 rdzenia) | własny parser XML zamiast `encoding/xml` (53% czasu), szybsza kompresja wewnętrzna, mniej alokacji, pula wątków i publikacja asynchroniczna; dokładanie kopii pomaga dopiero przy wolnych rdzeniach. **Zrobione 07.10.2026** |
| W2 | Surowy XML i pola dublują dane (80% miejsca) | krótka retencja kolumny `raw` (np. 1 dzień), pełny oryginał w archiwum Urd; plan pojemności. **Mechanizm zrobiony 07.10.2026** (domyślnie 5 dni do czasu archiwum) |
| W3 | „Spróbuj za 2 s” bez losowego rozrzutu, brak limitu przyjmowania | rozrzut w agencie; limit jednoczesnych żądań i 429 w ingest. **Zrobione 06.10.2026** |
| W4 | Certyfikaty: 3 miesiące, ręcznie, brak unieważniania, klucz CA tylko na stacji administratora | rejestracja tokenem, automatyczne odnawianie, lista unieważnień (etap 2 – obowiązkowo). **Zrobione 07.10.2026**: rejestracja tokenem, CA agentów (tylko certyfikaty klientów), odnawianie 30 dni przed końcem, unieważnianie przez NATS KV |
| W5 | Konfiguracja agenta wyłącznie lokalna | konfiguracja z serwera per grupa (etap 2). **Zrobione 07.10.2026** |
| W6 | Każdy element w jednej kopii na jednej VM | laboratorium: kopia VM w Proxmoxie; HA w etapie 8 |
| W7 | Writer po W1 jest najdroższym etapem: ok. 1,3 rdzenia przy 10 000 wierszy/s (rozpakowanie, JSON, przygotowanie kolumn) i sufit ok. 10–11 tys. wierszy/s na kopię | profil writera; lżejszy format wiadomości między normalizatorem a writerem; równoległe dekodowanie; kopie writera na osobnych rdzeniach |

**Mniejsze**
- M1: brak CI na GitHubie i testu wyścigów – **zrobione 07.10.2026** (GitHub Actions: Linux z `-race` i fuzzingiem, Windows z testami agenta);
- M2: nieczytelne wiadomości w normalizatorze są pomijane zamiast trafiać do kwarantanny – **zrobione 27.10.2026**: zdarzenia, których nie da się znormalizować, trafiają do kwarantanny (od 6b); cała nieczytelna paczka zostaje w archiwum NIS2 (archiwizator czyta kolejkę niezależnie), a *Stan systemu* pokazuje „Nieczytelne paczki (24 h)”;
- M3: brak czytelnego opisu większości zdarzeń (decyzja: opis renderowany przez agenta czy mapowanie na serwerze);
- M4: wyszukiwanie po mapie `fields` przy dużej skali – częste pola do osobnych kolumn;
- M5: Grafana i ingest otwarte na całą sieć lokalną, brak zapory na VM – **zrobione 27.10.2026**: rozdział „Zapora” w instrukcji instalacji (łańcuch DOCKER-USER – Docker omija ufw), `VARDR_GRAFANA_ADDR` (Grafana tylko z serwera); ingest musi zostać dostępny dla agentów;
- M6: brak raportowania synchronizacji czasu przez agenta (zaobserwowana różnica ok. 1 s) – **zrobione wcześniej (agent 0.6)**: agent mierzy różnicę zegara, panel zgłasza problem powyżej 60 s.

### Etap 1.5 – wykonane poprawki

**K1 – kolejka bez cichych strat (06.10.2026)**

- Oba strumienie mają retencję *interest*: wiadomość znika dopiero po potwierdzeniu przez wszystkich odbiorców, więc kolejka zawiera tylko zaległości. Limit rozmiaru z `discard: new` (domyślnie 8 GB na strumień), bez limitu wieku.
- Odbiorców (normalizator, writer) zakładają wszystkie usługi przy starcie, także ingest. Przy retencji *interest* wiadomość opublikowana przed powstaniem odbiorcy zostałaby od razu usunięta.
- Ingest sprawdza dwie rzeczy, zanim odczyta treść paczki:
  - więcej niż 64 paczki w obsłudze naraz → 429 i `Retry-After: 5`;
  - kolejka zajęta w ≥ 90% (pomiar co 2 s) albo NATS odmówił zapisu → 503 i `Retry-After: 30`.
- Normalizator i writer co minutę sprawdzają zajętość swojej kolejki. Od 50% zgłaszają ostrzeżenie, od 80% błąd z podpowiedzią, żeby dołożyć kopie.
- Ustawienia (zmienne środowiskowe, te same dla wszystkich usług): `SIEM_QUEUE_RAW_MAX_MB`, `SIEM_QUEUE_EVENTS_MAX_MB`, `SIEM_QUEUE_MAX_AGE` (domyślnie brak), `SIEM_INGEST_MAX_INFLIGHT`, `SIEM_INGEST_QUEUE_HIGH_WATER`.
- **Test na VM:** kolejka zmniejszona do 1 MB, normalizator zatrzymany, agent z pustym stanem wysyła całą historię (System 20 462 + Application 19 880 zdarzeń).
  - Kolejka zatrzymała się na 1 026 791 z 1 048 576 B.
  - Ingest odpowiadał 503, a agent czekał 30–45 s (Retry-After plus rozrzut).
  - Po włączeniu normalizatora w ClickHouse znalazło się **40 342 z 40 342** zdarzeń, kwarantanna pusta.
- Zmiana retencji istniejących strumieni (limits → interest) przeszła bez ich usuwania. Już przetworzone wiadomości zniknęły od razu, co zwolniło miejsce na dysku.

**K2 – wadliwy wiersz nie zatrzymuje zapisu (06.10.2026)**

- Writer rozróżnia błąd danych od awarii:
  - błąd danych: błąd konwersji wiersza albo wyjątek ClickHouse z listy kodów „złe dane”;
  - awaria: każdy inny błąd, w tym nieznany kod.
- Przy błędzie danych writer dzieli paczkę na połowy aż do pojedynczych wierszy. Złe wiersze trafiają do `siem.quarantine` z oryginałem i powodem, reszta jest zapisywana. Przy 2 złych wierszach na 1000 to mniej niż 45 prób zapisu (test jednostkowy).
- Lista kodów jest celowo zachowawcza: nieznany błąd jest ponawiany. Pomyłka w drugą stronę wysłałaby poprawne zdarzenia do kwarantanny, np. przy braku pamięci serwera.
- Normalizator zastępuje czasem przyjęcia czas zdarzenia spoza zakresu 1970–2200 (np. zerowy FILETIME) i oznacza go `time_quality=invalid`.
- Sprawdzone testami jednostkowymi. Na VM nie da się łatwo wywołać odrzucenia wiersza, bo korekta dat usuwa jedyną znaną przyczynę.

**W3 – rozrzut ponowień (06.10.2026)**

- Agent czeka co najmniej tyle, ile podaje `Retry-After`, plus losowe 0–50%. Przy kolejnych odmowach czas rośnie jak zwykły backoff.
- Dzięki temu tysiące agentów odrzuconych w tej samej chwili nie wracają w tej samej sekundzie.

**K4 – test obciążenia i metryki (06–07.10.2026)**

- `siem-loadgen` symuluje N agentów:
  - każdy ma własny certyfikat i połączenie TLS;
  - wysyła realistyczną mieszankę zdarzeń: 4624, 4634, 4688, 4625, Application 1000, System 7036 i 7045;
  - reaguje na 429 i 503 jak agent;
  - ma bufor z limitem (symulacja dziennika Windows) i liczy zdarzenia utracone po jego przepełnieniu.
- Metryki Prometheus w ingest, normalizatorze i writerze:
  - paczki według wyniku;
  - zdarzenia na etapach;
  - czasy pracy etapów;
  - opóźnienie od przyjęcia do zapisu;
  - zajętość i zaległości kolejek;
  - CPU i pamięć usług.

  Do tego metryki ClickHouse. Prometheus wykrywa kopie usług przez DNS Dockera. Pulpit Grafany: „SIEM – zdrowie potoku”.
- Wyniki na VM laboratoryjnej (4 vCPU, 10 GB RAM; generator na stacji w tej samej sieci):

| Test | Przyjęte przez ingest | Odmowy | Odpowiedź ingest p99 | W bazie | Obserwacje |
|---|---|---|---|---|---|
| 200 agentów × 10/s = 2000/s, 2 min | 259 832 (100%) | 0 | 6 ms | 259 832 (100%) od razu | opóźnienie potoku p99 2,6 s; CPU: ingest 0,66, normalizator 0,15, writer 0,25 rdzenia |
| 500 × 20/s = 10 000/s, 3 min, 1 normalizator | 1 899 141 (100%) | 374 × 429 (krótka przerwa, ok. 2 s) | 28 ms | 1 899 141 (100%), ale dopiero po ok. 4 min | **normalizator nie nadąża: ok. 4500/s**; kolejka urosła do 25 tys. paczek (1,4% limitu), opóźnienie potoku p99 ok. 200 s; ingest 0,5 rdzenia, writer 0,55, ClickHouse 0,3 |
| jak wyżej, 3 normalizatory | 1 898 969 (100%) | 1646 × 429 | 653 ms | 100% po opróżnieniu kolejki | **gorzej**: normalizatory zajęły 2,3 rdzenia i zagłodziły ingest, NATS i ClickHouse (INSERT p99 3,5 s). Na 4 vCPU dokładanie kopii nie pomaga |

- Wnioski:
  - Ingest, NATS, writer i ClickHouse przy 10 000 zdarzeń/s mają duży zapas (razem ok. 1,5 rdzenia).
  - Przeciążenie przebiegło zgodnie z założeniami: przyjęte 100% zdarzeń, 0 utraconych, 0 duplikatów, kwarantanna pusta.
  - Wąskie gardło to koszt normalizatora: na Ryzenie ok. 56 µs na zdarzenie za całą ścieżkę paczki, ok. 410 alokacji i 48 KB śmieci na zdarzenie.
  - Rozkład kosztu: parser XML 53%, JSON wyniku 16%, gzip wyniku 15%, odczyt JSON 10%.
  - Wcześniejszy benchmark (21–33 µs) mierzył tylko parsowanie.
  - Poziome skalowanie działa dopiero wtedy, gdy kopie mają własne rdzenie (osobne maszyny). Na jednej VM trzeba najpierw obniżyć koszt na zdarzenie (W1).

**W1 – wydajność normalizatora (07.10.2026)**

- **Własny parser XML** zdarzeń Windows zamiast `encoding/xml`: 3,8 µs zamiast 37,8 µs na zdarzenie (10×), 5 alokacji zamiast 388.
  - Zgodność ze starym parserem sprawdzają testy porównawcze: próbki, 3000 zdarzeń z generatora, przypadki brzegowe i wszystkie ucięcia prawdziwych zdarzeń.
  - Fuzzing: 43,7 mln losowych wejść bez różnicy w wynikach.
  - Celowe różnice: deklaracje `<!DOCTYPE>`, instrukcje `<?…?>` (poza `<?xml …?>`) i nazwy elementów spoza ASCII są odrzucane. Nie występują w zdarzeniach Windows, a ich odrzucenie zmniejsza powierzchnię ataku.
- **Kompresja wewnętrzna:** gzip na poziomie BestSpeed i ponowne używanie kompresorów.
- **JSON bez zamiany `<`, `>`, `&` na `\u003c`:** po stronie agenta, generatora i normalizatora. Surowy XML w paczkach jest krótszy i szybciej dekodowany. Format pozostaje zgodny, bo serwer czyta obie postaci.
- Cała ścieżka paczki: **56 → 19,9 µs na zdarzenie** (2,8×).
- **Równoległość:**
  - normalizator przetwarza paczki w puli wątków (`SIEM_NORMALIZER_WORKERS`, domyślnie liczba rdzeni);
  - writer zapisuje do ClickHouse w tle, a w tym czasie pobiera i dekoduje kolejną paczkę;
  - `GOGC=200` i `GOMEMLIMIT` w kontenerach zmniejszają koszt odśmiecania pamięci.
- Wyniki na tej samej VM (4 vCPU), jedna kopia każdej usługi:

| Test | Przed W1 | Po W1 |
|---|---|---|
| 10 000 zdarzeń/s, 3 min | normalizator 4500/s, kolejka 25 tys. paczek, opóźnienie potoku p99 ok. 200 s | normalizator nadąża (maks. 21 paczek w kolejce, 0,8 rdzenia), writer do 11 500 wierszy/s, **opóźnienie potoku p99 3–13 s**, 100% zdarzeń w bazie 10 s po końcu testu |
| 20 000 zdarzeń/s, 2 min | – | ingest przyjmuje 100% (720 krótkich odmów 429), normalizator do 17 000/s, writer ok. 10 000/s, VM wysycona (load 11 na 4 vCPU); 2 596 929 z 2 596 929 zdarzeń w bazie po opróżnieniu kolejki |

- Wniosek: przy 10 000 zdarzeń/s, czyli szacowanym szczycie dla firmy z roadmapy, cały potok mieści się na jednej VM z 4 vCPU. Następnym ograniczeniem są writer (W7) i liczba rdzeni. Dalej skaluje się dokładaniem rdzeni lub maszyn.
- **Korekta (etap 8, 12.10.2026):** powyższe pomiary miały 200–500 agentów z dużymi paczkami i bez detekcji. Przy **3500 agentach** po 1–3 zdarzenia/s paczki mają kilka zdarzeń, a koszt na paczkę (żądanie TLS, wiadomość w kolejce, każdy etap serwera) dominuje. Z pełną detekcją (oba silniki, korelacje, archiwum) ta sama VM:

| Test (3500 agentów, 10 min) | Wynik |
|---|---|
| 5000/s, paczki co 2 s (agent ≤ 0.7.0) | zaległość rośnie bez końca: writer ok. 2000/s (limit niepotwierdzonych wiadomości), detektor 400–1000/s (GC przy 200 MiB, zapis alertów po 4 polecenia na trafienie, kontekst progów porcjami po 500 kluczy), korelacja ponad limit pamięci ClickHouse |
| 5000/s po poprawkach, paczki co 2 s | writer i detektor po ok. 3000/s – VM wysycona (load 24, 0% bezczynności) narzutem na paczkę |
| 5000/s, paczki do 10 s (agent 0.7.1) | **wszystkie etapy nadążają**, kolejki ≈ 0, opóźnienie potoku p99 2,5–6 s, 0,1% odmów 429, 24% CPU wolne |
| 10 000/s, paczki do 10 s | VM wysycona (CPU 100%, ingest i NATS na limitach pamięci, swap); zaległość ok. 100 tys. wiadomości odrobiona 9 min po teście; **6 299 835 / 6 299 835 zdarzeń w bazie** |

- **Ta sama VM z 8 vCPU (13.10.2026):** 10 000 zdarzeń/s stabilnie (opóźnienie p99 3 s, 29% CPU wolne); 15 000/s wysyca VM, ale bez strat – 9 455 168 / 9 455 168 zdarzeń po ok. 9 min nadrabiania. Pamięć 10 GB wystarcza po podniesieniu limitów writera (1 GB) i detektora (1 GB).
- Koszt całego stosu: ok. **0,6 rdzenia na 1000 zdarzeń/s** (z ClickHouse, PostgreSQL, NATS i detekcją). Szacunek dla 15 000 zdarzeń/s: ok. 9–10 rdzeni pod obciążeniem, czyli serwer 16 rdzeni / 32 GB z zapasem; w laboratorium (4 vCPU, 10 GB) bezpiecznie ok. 5000/s.

**W2 – osobna retencja surowego XML (07.10.2026)**

- Kolumna `raw` ma własny TTL (`SIEM_RAW_TTL_DAYS`, nie dłuższy niż `SIEM_EVENTS_TTL_DAYS`). Po jego upływie ClickHouse czyści oryginalny XML, a wiersz i pola znormalizowane zostają.
- Sprawdzone na VM:
  - działa razem z `ttl_only_drop_parts=1`;
  - świeża instalacja tworzy kolumnę z TTL;
  - `clickhouse/retention.sh` zmienia retencję działającej bazy na podstawie `.env`.
- **Decyzja (07.10.2026):** domyślnie 5 dni, czyli bez zmiany, dopóki nie powstanie archiwum NIS2 (Urd, etap 3). Do tego czasu oryginały są dostępne tylko w ClickHouse.
- Pomiar po testach obciążenia: `fields` 495 MiB, `raw` 484 MiB, razem ok. 85% tabeli. Skrócenie retencji `raw` do 1 dnia zmniejszy bazę o ok. 35% przy 5 dniach retencji.

**K3 – ochrona przed nadpisaniem dziennika Windows (07.10.2026)**

- Agent odczytuje stan dziennika z Windows API: liczbę rekordów, numer najstarszego, rozmiar pliku i maksymalny, tryb nadpisywania. Wartości zgadzają się z `Get-WinEvent -ListLog`.
- **Co minutę** liczy, jaką część pojemności dziennika zajmują rekordy nowsze niż pozycja agenta:
  - od 50% ostrzeżenie, od 80% alarm;
  - szacunek czasu do nadpisania z tempa zapisu i pojemności dziennika;
  - komunikat raz przy przekroczeniu progu, informacja po odrobieniu zaległości.
- Pozycję liczy ostrożnie: czytnik widzi tylko zdarzenia pasujące do filtra Event ID. Gdy czytnik był na bieżąco (subskrypcja opróżniona albo brak sygnału), za pozycję przyjmowany jest najnowszy rekord dziennika. Agent na bieżąco nie dostaje fałszywych alarmów, nawet gdy dziennik zawija się zdarzeniami spoza filtra (test).
- **Luki w danych** są zgłaszane z dokładnym zakresem rekordów:
  - przy wznowieniu po przerwie, gdy zapisana pozycja jest starsza niż najstarszy rekord dziennika (Windows wznawia wtedy po cichu od najstarszego);
  - w trakcie pracy (błąd „wyniki nieaktualne” subskrypcji, wykrywany już wcześniej, teraz zgłaszany także w statusie i w Podglądzie zdarzeń).
- Przy starcie: podpowiedź dla dziennika Security mniejszego niż 128 MB i ostrzeżenie przed trybem „nie nadpisuj”.
- Sprawdzone na żywo na kanale, który się już zawinął (`Microsoft-Windows-Shell-Core/Operational`, najstarszy rekord 38 054). Agent wznawiający od rekordu 1000 zgłosił „LUKA W DANYCH: rekordy 1001–38053”, a przy nieosiągalnym serwerze ostrzeżenie o zajętości 78%. Oba komunikaty trafiły do `vardr-agent status`.
- Zalecenia rozmiarów dzienników dla GPO: README, sekcja „Rozmiar dzienników Windows”.
