# Heimdall – podsumowanie etapów

Stan na 07.10.2026 (wersja `2e26bff`). Plik zbiera, co zrobiono w każdym etapie, jak to sprawdzono i czego świadomie jeszcze nie ma. Plan i uzasadnienia są w [ROADMAP.md](ROADMAP.md), instrukcje obsługi w [README.md](../README.md).

Kolejność prac różni się od numeracji w roadmapie. Po etapie 1 był etap 1.5 (wzmocnienie), potem etap 2 razem z pierwszymi modułami panelu (część etapu 5), potem etap 3. Detekcja (etap 4) jest następna.

---

## Etap 0 – Fundamenty

**Cel:** repozytorium, CI, kontrakt paczki agent → serwer, schemat zdarzenia, polityka audytu, laboratorium.

**Zrobione:**
- repozytorium Go z podziałem `agent/`, `server/`, `panel/`, `tools/` i wspólnym `internal/` (reorganizacja `7f341e1`);
- kontrakt paczki i stałe identyfikatory zdarzeń (roadmapa, załącznik A; kod `internal/contract`);
- domyślna lista zdarzeń Windows i zalecenia polityki audytu GPO (załącznik B, README);
- nazewnictwo (załącznik D) i model skalowania (załącznik E);
- VM laboratoryjna w Proxmoxie (192.168.88.98) ze stosem w Dockerze.

**Brakuje:**
- **laboratorium AD**, czyli kontrolera domeny i 2–3 stacji z polityką audytu i Sysmonem. Testy szły na jednym komputerze z Windows i na generatorze ruchu. Przed etapem 4 to blokada: scenariusze detekcji (4625 na koncie domenowym, 4728/4732, Kerberos, password spraying) wymagają prawdziwego DC.

---

## Etap 1 – Szkielet end-to-end

**Cel:** zdarzenie z Windows widoczne w wyszukiwarce i śledzone po stałym ID.

**Zrobione:**
- **Agent Windows** (`siem_agent`):
  - odczyt Event Log z bookmarkiem;
  - paczki gzip po TLS 1.3 z certyfikatem klienta;
  - pozycja zapisywana dopiero po potwierdzeniu serwera, więc możliwe są duplikaty, ale nie luki;
  - kopia stanu w rejestrze;
  - ochrona plików i blokada niebezpiecznych ścieżek usługi;
  - limity CPU, pamięci, zdarzeń na sekundę i łącza;
  - diagnostyka (`status`, Podgląd zdarzeń) i instalator `siem_agent install`.
- **Potok serwera:** `siem-ingest` (mTLS) → NATS JetStream → `siem-normalizer` (ECS) → `siem-writer` → ClickHouse; podgląd w Grafanie.

**Sprawdzone:** 40 123 / 40 123 zdarzeń po twardym zabiciu agenta, 30% odrzuceń 503 i wyłączeniu serwera, bez braków.

## Etap 1.5 – Wzmocnienie (przegląd K1–K4, W1–W3, M1)

**Zrobione:**
- **K1:** kolejka bez cichych strat (retencja do potwierdzenia, `discard: new`, 503/429 w ingest);
- **K2:** writer dzieli paczkę i odkłada wadliwy wiersz do kwarantanny;
- **K3:** ostrzeżenie agenta przed nadpisaniem dziennika i zalecenia GPO;
- **K4:** generator ruchu, metryki Prometheus, pulpit „zdrowie potoku”;
- **W1:** własny parser XML, równoległy normalizator (na VM ok. 4500 → 17 000 zdarzeń/s na kopię);
- **W2:** osobna, krótsza retencja surowego XML (mechanizm);
- **W3:** rozrzut ponowień w agencie;
- **M1:** GitHub Actions: Linux z `-race` i fuzzingiem, Windows, build frontendu.

**Sprawdzone:** potok nadąża przy 10 000 zdarzeń/s na VM z 4 vCPU.

**Do zrobienia później:** wydajność writera (W7, sufit ok. 10–11 tys. wierszy/s na kopię).

---

## Etap 2 – Niezawodny agent + moduły 1–4 panelu

**Zrobione:**
- **Panel Hliðskjálf** (`siem-api`, React + Mantine, HTTPS :8444, baza Saga/PostgreSQL):
  - **logowanie i role:** administrator, analityk, tylko odczyt; sesje, CSRF, blokada konta po nieudanych próbach, dziennik audytu;
  - **Huginn:** heartbeat agentów co minutę, lista i szczegóły agenta, problemy agenta;
  - **Bifröst:** tokeny rejestracyjne (skrót w bazie, limit instalacji, ważność, grupa) i paczka ZIP bez klucza prywatnego. Do tego CA agentów, automatyczne odnawianie i unieważnianie certyfikatów oraz `siem_agent upgrade`;
  - **Mímir:** wyszukiwarka z językiem zapytań, histogramem, szczegółami i surowym XML; konto ClickHouse tylko do odczytu;
  - **grupy agentów:** profil zdarzeń i limity; agent 0.5.0 pobiera konfigurację co 5 min i stosuje ją bez restartu.

**Sprawdzone:** 1000 symulowanych agentów w panelu.

**Brakuje względem warunku ukończenia z roadmapy:**
- **instalator MSI** z cichą instalacją (jest ZIP z `install.cmd`);
- **bufor dyskowy agenta**: dziś buforem jest dziennik Windows, plus ostrzeżenia K3;
- formalny test „30 min bez sieci + rotacja dziennika bez luk” jako scenariusz akceptacyjny. Mechanizm jest, ale testu nie zapisano.

---

## Etap 3 – Archiwum NIS2 (Urd) – zakończony

**Cel:** oryginały logów chronione przed niezauważoną zmianą; usunięcie lub podmiana paczki wykrywane; replay z archiwum działa.

**Zrobione:**
1. **Archiwizator** (`siem-archiver`):
   - osobny odbiorca kolejki `SIEM_RAW`;
   - segmenty z `fsync`, tylko do odczytu, potwierdzane po zapisie;
   - godzinowe manifesty z łańcuchem SHA-256, także dla pustych godzin;
   - spis w Sadze (schemat `urd`);
   - jeden archiwizator, pilnowany blokadą w PostgreSQL.
2. **Weryfikacja:**
   - co 6 h tanie sprawdzenie całości (łańcuch, obecność i rozmiar plików, pliki obce, przerwy);
   - pełne SHA-256 w budżecie 50 GB na przebieg, kolejno po całym archiwum;
   - `verify --full` na żądanie.
3. **Panel Urd:**
   - stan zgodności (10 stanów), łańcuch manifestów, historia weryfikacji;
   - weryfikacja na żądanie z audytem;
   - kafelek na stronie startowej.
4. **Wzmocnienie po przeglądzie:**
   - osobne role bazy (`saga_admin`, `siem_api`, `siem_archiver`, `urd_reader`);
   - osobny dysk 150 GB z ochroną przed pisaniem na dysk systemowy;
   - wstrzymanie archiwizacji przy braku miejsca;
   - nocne kopie bazy;
   - 11 reguł alertów w Grafanie;
   - `deploy.sh` z wersją z gita.
5. **Eksport dla audytora** (format `heimdall-urd-export/2`):
   - część czytelna: NDJSON z polami ECS i oryginalnym XML oraz CSV;
   - dowód: segmenty, łańcuch, kotwica, `SHA256SUMS`;
   - niezależny skrypt w Pythonie;
   - `odczytaj.exe` z raportem po polsku;
   - `check-export`;
   - audyt zlecenia i pobrania;
   - filtr źródeł.
6. **Replay:** osobna ścieżka NATS, kopie normalizatora i writera, tabela `siem.events_replay` (TTL 7 dni) i przełącznik w Mímirze.
7. **Polityka w panelu:**
   - włączenie, retencja w granicach z konfiguracji serwera, wyłączanie grup i agentów;
   - osłabienie wymaga hasła, ma 24 h karencji, alert i możliwość anulowania;
   - archiwizator jest jedynym, który zmienia politykę.

**Sprawdzone na VM:**
- 2427/2427 paczek testu obciążenia w archiwum;
- zmiana jednego bajtu w segmencie wykryta (i po przywróceniu znika);
- test kopii zapasowej z odtworzeniem;
- przeniesienie archiwum na nowy dysk z porównaniem SHA-256;
- symulacja braku dysku;
- eksport 100 117 zdarzeń sprawdzony przez Go i Pythona; sfałszowany Event ID wykryty przez oba;
- `odczytaj.exe` na Windows: wynik ZGODNE, ok. 5 s;
- replay 100 117 zdarzeń zgodnych z `siem.events`;
- polityka: uprawnienia ról, karencja, odrzucenie retencji poniżej minimum, anulowanie, pomijanie wyłączonego agenta, alert w Grafanie.

**Świadome uproszczenia:**
- dysk lokalny bez blokady zapisu (WORM); backend S3 z Object Lock (compliance) później;
- jedna retencja dla całego archiwum; retencja per źródło po MVP;
- eksport z filtrem nadal zawiera w segmentach dane wszystkich źródeł z wybranych godzin;
- alert przy niezgodności idzie przez Grafanę, nie przez Gjallarhorn (etap 4).

---

## Etap 4 – Detekcja (Gjallarhorn) – zakończony

- **4a (09.10):** kompilator podzbioru Sigmy w Go (`server/internal/detect`) – selekcje, modyfikatory, maski, warunki, aliasy pól (Sysmon 1 ↔ Security 4688); rozszerzenia Heimdalla (`mode`, `group_by`, `suppress`, `instructions` ze zmiennymi `{{Pole}}`, `enabled`); reguły w repozytorium (`rules/`), nieobsługiwane konstrukcje jawnie odrzucane.
- **4b (09.10):** `siem-detector` – osobny odbiorca `SIEM_EVENTS`, alerty w Sadze (schemat `gjallarhorn`, rola `siem_detector`), para (reguła, zdarzenie) najwyżej raz, łączenie trafień w oknie, outbox → kanały powiadomień, moduł Gjallarhorn i „Reguły detekcji” w panelu. Sprawdzone w laboratorium AD (PowerShell -EncodedCommand, podejrzany skrypt, usługa z katalogu użytkownika, Backup Operators, nowe konto).
- **4c (09.10):** reguły progowe `heimdall.threshold` (`count` / `distinct` w oknie po czasie zdarzenia, klucz `group_by`). Stan progów zapisywany w tej samej transakcji co alerty (`gjallarhorn.threshold_events`) i odtwarzany po restarcie albo nieudanym zapisie. Reguły: brute force (4625), brute force Kerberos (4771/0x18), password spraying (≥ 5 różnych kont z jednego adresu). Sprawdzone w laboratorium: 12 błędnych logowań LDAP → alert brute force, 6 kont z jednej stacji → alert password spraying, restart detektora odtworzył stan. Przy okazji: `deploy.sh rules` przełącza wersje reguł atomowo (dowiązanie `rules/current`) – wcześniej podmiana katalogu odcinała go działającemu detektorowi.
- **4d (09.10):** silnik zapytań – kompilator reguł do SQL ClickHouse (`detect/sql.go`), przebiegi co minutę po czasie przyjęcia z punktem kontrolnym w Sadze, progi liczone wspólnym kodem z kontekstem z ClickHouse; `SIEM_DETECTION_MODE` (stream / index_query / both); konto `siem_detector` w ClickHouse i indeks `idx_ingested`. Semantyka progów ujednolicona i niezależna od kolejności (okna + łańcuch po `suppress`, zaczepiony także o zdarzenia już w alercie). Test zgodności na prawdziwym ClickHouse: 14 reguł (w tym testowe z wszystkimi modyfikatorami) – identyczne dopasowania Go/SQL i identyczne trafienia obu silników (124) przy 3 kolejnościach napływu; w CI razem z testami Sagi. Laboratorium: w trybie tylko-zapytania brute force na nowe konto → alert #10 założony przez silnik zapytań, spraying z tego samego adresu dopisany do trwającego alertu #9. Przy okazji: Prometheus od 4b nie zbierał metryk detektora (`deploy.sh config` podmieniał zamontowany plik – teraz `tar --overwrite` + przeładowanie), naprawione maski z „/” w regułach, alerty Grafany dla detektora (nie działa, zaległość silnika zapytań, błędy reguł).
- **4e (09.10):** reguła wbudowana „Utrata łączności z agentem” (próg w grupie agentów, jedna przerwa = jeden alert, automatyczne zamknięcie po powrocie, pomijanie agentów wycofanych; detektor czyta tabele panelu przez osobne uprawnienia), reguły Sigma: wyczyszczenie innych dzienników (System 104) i zatrzymanie/awaria usługi agenta albo Sysmona (7036/7031/7034, tekst stanu po angielsku i polsku). Laboratorium: wyczyszczenie dziennika Security na stacji → alert 1102 w kilka sekund, agent czyta dziennik dalej; zatrzymanie agenta na DC → alert utraty łączności po progu, zdarzenia z czasu przerwy doczytane po starcie, alert zamknięty automatycznie; restart usługi → alert zatrzymania usługi. Grupa DC ma próg 15 min.
- **Kryterium etapu (roadmapa):** scenariusze Windows z sekcji 11 wykrywane w obu silnikach (test zgodności w CI + próby w laboratorium), restart i ponowne dostarczenie nie dublują alertów (para reguła–zdarzenie raz; stan progów w Sadze). Poza zakresem do czasu integracji: VPN FortiGate i Entra ID (logowanie z nowego kraju).

## Przegląd etapu 4 (09.10.2026) – błędy i luki

Priorytety jak niżej: **W** – ważne, **Ś** – średnie, **N** – niskie.

| # | Pr. | Problem | Skutek | Stan |
|---|---|---|---|---|
| 1 | W | Zalew nieudanych logowań na jedno konto: silnik w locie przeliczał wszystkie okna klucza przy każdym zdarzeniu (0,3 ms i 126 KB na zdarzenie przy 8 tys. w pamięci) | atakujący mógł zapchać detekcję własnym brute force – kolejka rośnie, ingest zaczyna odmawiać | **naprawione:** szybka ścieżka dla zdarzeń przedłużających trwający alert – 9 µs i 5 KB (32× szybciej) |
| 2 | W | Brak globalnego limitu pamięci stanu progów (detektor ma 256 MB) | po braku pamięci detektor odtwarzał ten sam stan z bazy – pętla restartów, detekcja wyłączona | **naprawione:** limit 200 tys. zdarzeń w pamięci, nadmiar liczony w metryce (silnik zapytań go nadrabia) |
| 3 | W | Silnik zapytań: ponad 50 tys. pasujących zdarzeń w 5-minutowej zakładce | punkt kontrolny staje, przebieg co sekundę czyta te same wiersze | **naprawione:** kursor (czas przyjęcia, id zdarzenia), dalszy ciąg bez zakładki; test z limitem 7 wierszy |
| 4 | W | Silnik zapytań: kontekst progów dla tysięcy kluczy w jednym zapytaniu | przekroczony limit rozmiaru SQL – silnik stoi do ręcznej interwencji | **naprawione:** paczki po 500 kluczy |
| 5 | W | Discord: wartości ze zdarzeń (polecenie, konto) trafiały do wiadomości jako Markdown | atakujący może podsunąć w kanale SOC link „[Otwórz alert w panelu](https://…)” | **naprawione:** escapowanie Markdownu w danych ze zdarzeń; link do panelu i czas bez zmian; test |
| 6 | Ś | Jedna reguła z SQL odrzuconym przez ClickHouse wywraca zapytanie łączne | silnik zapytań przestaje działać dla wszystkich reguł | **naprawione:** reguła izolowana i pomijana, metryka + alert Grafany (ClickHouse 25.8 przyjmuje wszystkie składnie regexów Go, które sprawdziłem – ryzyko małe) |
| 7 | Ś | Discord odrzuca embed > 6000 znaków, a powiadomienie było ponawiane w nieskończoność | alert bez powiadomienia, wpis w outboxie co godzinę na zawsze | **naprawione:** łączny limit (skracanie najdłuższych pól), porzucenie po 30 próbach (ok. doby) z logiem |
| 8 | Ś | Silnik zapytań co minutę zapisywał od nowa trafienia z zakładki | tysiące zbędnych zapisów w Sadze przy aktywnej regule | **naprawione:** jedno zapytanie odsiewa pary (reguła, zdarzenie) już będące w alertach |
| 9 | W | (4c/4d) `deploy.sh rules` odcinał katalog reguł działającemu detektorowi; Prometheus nie zbierał metryk detektora od 4b; maski z „/” nigdy nie pasowały | reguły nie przeładowywały się; brak metryk i alertów zdrowia detekcji | **naprawione wcześniej** (atomowe dowiązanie `rules/current`, `tar --overwrite` + przeładowanie Prometheusa) |
| 10 | Ś | Burza alertów: każdy alert to osobna wiadomość (Discord przyjmuje ok. 30/min) | przy hałaśliwej regule kanał zalany, ważne alerty giną w tłumie | **otwarte** – zbiorcze powiadomienia i limit na regułę (etap 5) |
| 11 | Ś | Lista alertów w panelu: najnowsze 100, bez stronicowania | starsze otwarte alerty widać tylko filtrami | **otwarte** – etap 5 |
| 12 | Ś | Jeden detektor (blokada w Sadze) – brak drugiej kopii w gotowości | restart/awaria = przerwa w detekcji (zdarzenia czekają w kolejce, nic nie ginie; alert Grafany po 3 min) | świadoma decyzja MVP; druga kopia czekająca na blokadę – później |
| 13 | N | Powrót agenta zamyka alert utraty łączności bez powiadomienia | analityk nie wie z Discorda, że problem minął | do decyzji: wiadomość „agent wrócił” |
| 14 | N | W tabeli agentów jest 50 nieaktywnych wpisów (symulacje z etapu 2) | po ustawieniu progu w grupie domyślnej każdy da alert utraty łączności | do wycofania w panelu (unieważnienie certyfikatów) albo usunięcia |
| 15 | N | Zamknięcie alertu progowego w trakcie trwającego ataku | kolejne próby otwierają nowy alert (od 1 trafienia, z opisem progu) | zachowanie zamierzone – zamknięcie oznacza „obsłużone”; opisane tutaj |
| 16 | N | Reguła zatrzymania usługi alarmuje także przy aktualizacji agenta (MSI) | fałszywy alert przy każdej aktualizacji | wyciszenie po korelacji z instalatorem (MsiInstaller) – v1 |
| 17 | N | Pole `Channel` z danych zdarzenia 104 (nazwa wyczyszczonego dziennika) zasłania nazwa Sigmy `Channel` (kanał zdarzenia) | instrukcja alertu nie podaje nazwy dziennika (jest w polach zdarzenia) | do poprawy przy mapowaniu pól UserData |
| 18 | N | Słowa kluczowe w silniku zapytań po 2 dniach przeszukują tylko opis (retencja surowego XML) | starsze zdarzenia mogą nie pasować do reguł ze słowami kluczowymi | udokumentowane (README) |

**Co sprawdzono i jest w porządku:** uprawnienia API alertów (odczyt – viewer, zmiana stanu – analityk, powód zamknięcia, audyt); outbox z `FOR UPDATE SKIP LOCKED` (dwie kopie panelu nie wyślą tego samego); blokada wzmianek w Discordzie (`@everyone` nie działa); kompilator SQL – literały escapowane, zgodność z Go potwierdzona na wszystkich modyfikatorach; idempotencja zapisu (para reguła–zdarzenie raz) przy restartach, ponownym dostarczeniu i obu silnikach naraz; agent po wyczyszczeniu dziennika Security czyta dalej; zdarzenia z czasu zatrzymania agenta są doczytywane.

## Przegląd z lotu ptaka (07.10.2026) – niedociągnięcia i luki

Priorytety: **W** = ważne (bezpieczeństwo lub poprawność), **Ś** = średnie, **N** = niskie lub porządkowe.

| # | Pr. | Problem | Skutek | Propozycja |
|---|---|---|---|---|
| 1 | W | Grafana nie ma punktu kontaktowego – alerty nikogo nie powiadamiają | karencja 24 h dla osłabień polityki i wszystkie alerty zdrowia działają tylko, gdy ktoś akurat patrzy w Grafanę | **zrobione 08.10:** kanały powiadomień w panelu (Discord, webhook), Grafana przekazuje alerty przez siem-api |
| 2 | W | Przeniesienie agenta do wyłączonej grupy (albo token z taką grupą) nie jest traktowane jak osłabienie | administrator bez hasła i bez karencji może wyłączyć agenta z archiwum, przypisując go do wyłączonej grupy | **zrobione 08.10:** archiwizator zapisuje czas wejścia agenta do grupy (`urd.group_membership`), wykluczenie po karencji |
| 3 | W | Kotwica łańcucha tylko w systemie | ktoś z dostępem do dysku **i** bazy może przepisać cały łańcuch bez śladu | **zrobione 08.10:** codzienna kotwica na kanały powiadomień, porównanie z łańcuchem w panelu |
| 4 | W | Kopie zapasowe (z kluczem CA agentów i `.env`) leżą na tej samej VM | utrata VM = utrata kopii | **zrobione 08.10:** kopie szyfrowane hasłem administratora (gpg), codziennie na TrueNAS razem z przyrostami archiwum; `restore.sh` – do przećwiczenia na czystej VM |
| 5 | Ś | Archiwum i paczki eksportu nie są szyfrowane (decyzja odłożona: eksport ma być łatwy do odczytu) | dane osobowe (konta, adresy IP) w jawnej postaci na dysku i w paczce przekazywanej na zewnątrz | LUKS na dysku archiwum (wymaga sformatowania; sudo); opcjonalne szyfrowanie paczki eksportu |
| 6 | Ś | Brak laboratorium AD | etap 4 nie ma na czym sprawdzić scenariuszy detekcji | postawić DC + stację przed etapem 4 |
| 7 | Ś | Etap 2 oznaczony jako zakończony mimo braku MSI i bufora dyskowego | roadmapa myląca | **zrobione 08.10:** agent 0.6 – bufor dyskowy z limitem w grupie agentów i instalator MSI (do przetestowania na stacjach laboratorium) |
| 8 | Ś | Minimalizacja danych w eksporcie z filtrem | organ dostaje w segmentach także dane innych źródeł | manifest v2 z indeksem rekordów pozwoli udowodnić pojedyncze paczki bez całego segmentu |
| 9 | Ś | Agent nie raportuje synchronizacji zegara (roadmapa, sekcja 6) | błędny zegar komputera widać tylko po `time_quality` w normalizatorze | **zrobione 08.10:** odchylenie zegara względem serwera (heartbeat) i stan usługi W32Time w panelu |
| 10 | N | README: nieaktualna sekcja „Czego jeszcze nie ma” i lista alertów bez dwóch nowych reguł | dokumentacja | **zrobione 07.10** |
| 11 | N | Decyzja o retencji surowego XML w ClickHouse (dziś 5 dni) | miejsce na dysku | **zrobione 08.10:** surowy XML 2 dni (oryginały w Urd) |
| 12 | N | `odczytaj.exe` bez podpisu cyfrowego | ostrzeżenie SmartScreen u odbiorcy | certyfikat code signing, gdy projekt wyjdzie poza laboratorium |
| 13 | N | Wpisy testowe w bazie (`test-eksportu`, `test-odtworzenia`, `test-polityki`) i ~270 MB starych danych testowych w `data/` | porządek | **zrobione 08.10:** `data/` usunięty; historia polityki zostaje jako dziennik |
