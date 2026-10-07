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

## Przegląd z lotu ptaka (07.10.2026) – niedociągnięcia i luki

Priorytety: **W** = ważne (bezpieczeństwo lub poprawność), **Ś** = średnie, **N** = niskie lub porządkowe.

| # | Pr. | Problem | Skutek | Propozycja |
|---|---|---|---|---|
| 1 | W | Grafana nie ma punktu kontaktowego – alerty nikogo nie powiadamiają | karencja 24 h dla osłabień polityki i wszystkie alerty zdrowia działają tylko, gdy ktoś akurat patrzy w Grafanę | dodać webhook Discorda w Grafanie (decyzja odłożona) |
| 2 | W | Przeniesienie agenta do wyłączonej grupy (albo token z taką grupą) nie jest traktowane jak osłabienie | administrator bez hasła i bez karencji może wyłączyć agenta z archiwum, przypisując go do wyłączonej grupy | archiwizator traktuje przypisanie młodsze niż karencja jak brak wykluczenia (`agent_assignments.updated_at`), panel to pokazuje |
| 3 | W | Kotwica łańcucha tylko w systemie | ktoś z dostępem do dysku **i** bazy może przepisać cały łańcuch bez śladu | codzienne wysłanie kotwicy poza system (webhook lub e-mail) i/lub znacznik czasu RFC 3161 z zewnętrznego TSA |
| 4 | W | Kopie zapasowe (z kluczem CA agentów i `.env`) leżą na tej samej VM | utrata VM = utrata kopii | okresowe kopiowanie na inny komputer, najlepiej zaszyfrowane |
| 5 | Ś | Archiwum i paczki eksportu nie są szyfrowane | dane osobowe (konta, adresy IP) w jawnej postaci na dysku i w paczce przekazywanej na zewnątrz | LUKS na dysku archiwum (wymaga sformatowania; sudo); opcjonalne szyfrowanie paczki eksportu |
| 6 | Ś | Brak laboratorium AD | etap 4 nie ma na czym sprawdzić scenariuszy detekcji | postawić DC + stację przed etapem 4 |
| 7 | Ś | Etap 2 oznaczony jako zakończony mimo braku MSI i bufora dyskowego | roadmapa myląca | poprawić opis w roadmapie, MSI i bufor jako osobne zadania |
| 8 | Ś | Minimalizacja danych w eksporcie z filtrem | organ dostaje w segmentach także dane innych źródeł | manifest v2 z indeksem rekordów pozwoli udowodnić pojedyncze paczki bez całego segmentu |
| 9 | Ś | Agent nie raportuje synchronizacji zegara (roadmapa, sekcja 6) | błędny zegar komputera widać tylko po `time_quality` w normalizatorze | dodać stan synchronizacji czasu do heartbeatu |
| 10 | N | README: nieaktualna sekcja „Czego jeszcze nie ma” i lista alertów bez dwóch nowych reguł | dokumentacja | poprawione razem z tym plikiem |
| 11 | N | Decyzja o retencji surowego XML w ClickHouse (dziś 5 dni) | miejsce na dysku | po etapie 3 oryginał jest w archiwum – można skrócić do 1–2 dni |
| 12 | N | `odczytaj.exe` bez podpisu cyfrowego | ostrzeżenie SmartScreen u odbiorcy | certyfikat code signing, gdy projekt wyjdzie poza laboratorium |
| 13 | N | Wpisy testowe w bazie (`test-eksportu`, `test-odtworzenia`, `test-polityki`) i ~270 MB starych danych testowych w `data/` | porządek | eksporty i replay wygasają same; historia polityki zostaje (to dziennik) |
