# Heimdall – podsumowanie etapów

Stan na 12.10.2026 (etap 7). Plik zbiera, co zrobiono w każdym etapie, jak to sprawdzono i czego świadomie jeszcze nie ma. Plan i uzasadnienia są w [ROADMAP.md](ROADMAP.md), instrukcje obsługi w [README.md](../README.md).

Kolejność prac różni się od numeracji w roadmapie. Po etapie 1 był etap 1.5 (wzmocnienie), potem etap 2 razem z pierwszymi modułami panelu (część etapu 5), potem etapy 3–7. W toku: etap 8.

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

- **4a (09.10):** kompilator podzbioru Sigmy w Go (`internal/detect`) – selekcje, modyfikatory, maski, warunki, aliasy pól (Sysmon 1 ↔ Security 4688); rozszerzenia Heimdalla (`mode`, `group_by`, `suppress`, `instructions` ze zmiennymi `{{Pole}}`, `enabled`); reguły w repozytorium (`rules/`), nieobsługiwane konstrukcje jawnie odrzucane.
- **4b (09.10):** `siem-detector` – osobny odbiorca `SIEM_EVENTS`, alerty w Sadze (schemat `gjallarhorn`, rola `siem_detector`), para (reguła, zdarzenie) najwyżej raz, łączenie trafień w oknie, outbox → kanały powiadomień, moduł Gjallarhorn i „Reguły detekcji” w panelu. Sprawdzone w laboratorium AD (PowerShell -EncodedCommand, podejrzany skrypt, usługa z katalogu użytkownika, Backup Operators, nowe konto).
- **4c (09.10):** reguły progowe `heimdall.threshold` (`count` / `distinct` w oknie po czasie zdarzenia, klucz `group_by`). Stan progów zapisywany w tej samej transakcji co alerty (`gjallarhorn.threshold_events`) i odtwarzany po restarcie albo nieudanym zapisie. Reguły: brute force (4625), brute force Kerberos (4771/0x18), password spraying (≥ 5 różnych kont z jednego adresu). Sprawdzone w laboratorium: 12 błędnych logowań LDAP → alert brute force, 6 kont z jednej stacji → alert password spraying, restart detektora odtworzył stan. Przy okazji: `deploy.sh rules` przełącza wersje reguł atomowo (dowiązanie `rules/current`) – wcześniej podmiana katalogu odcinała go działającemu detektorowi.
- **4d (09.10):** silnik zapytań – kompilator reguł do SQL ClickHouse (`detect/sql.go`), przebiegi co minutę po czasie przyjęcia z punktem kontrolnym w Sadze, progi liczone wspólnym kodem z kontekstem z ClickHouse; `SIEM_DETECTION_MODE` (stream / index_query / both); konto `siem_detector` w ClickHouse i indeks `idx_ingested`. Semantyka progów ujednolicona i niezależna od kolejności (okna + łańcuch po `suppress`, zaczepiony także o zdarzenia już w alercie). Test zgodności na prawdziwym ClickHouse: 14 reguł (w tym testowe z wszystkimi modyfikatorami) – identyczne dopasowania Go/SQL i identyczne trafienia obu silników (124) przy 3 kolejnościach napływu; w CI razem z testami Sagi. Laboratorium: w trybie tylko-zapytania brute force na nowe konto → alert #10 założony przez silnik zapytań, spraying z tego samego adresu dopisany do trwającego alertu #9. Przy okazji: Prometheus od 4b nie zbierał metryk detektora (`deploy.sh config` podmieniał zamontowany plik – teraz `tar --overwrite` + przeładowanie), naprawione maski z „/” w regułach, alerty Grafany dla detektora (nie działa, zaległość silnika zapytań, błędy reguł).
- **4e (09.10):** reguła wbudowana „Utrata łączności z agentem” (próg w grupie agentów, jedna przerwa = jeden alert, automatyczne zamknięcie po powrocie, pomijanie agentów wycofanych; detektor czyta tabele panelu przez osobne uprawnienia), reguły Sigma: wyczyszczenie innych dzienników (System 104) i zatrzymanie/awaria usługi agenta albo Sysmona (7036/7031/7034, tekst stanu po angielsku i polsku). Laboratorium: wyczyszczenie dziennika Security na stacji → alert 1102 w kilka sekund, agent czyta dziennik dalej; zatrzymanie agenta na DC → alert utraty łączności po progu, zdarzenia z czasu przerwy doczytane po starcie, alert zamknięty automatycznie; restart usługi → alert zatrzymania usługi. Grupa DC ma próg 15 min.
- **Kryterium etapu (roadmapa):** scenariusze Windows z sekcji 11 wykrywane w obu silnikach (test zgodności w CI + próby w laboratorium), restart i ponowne dostarczenie nie dublują alertów (para reguła–zdarzenie raz; stan progów w Sadze). Poza zakresem do czasu integracji: VPN FortiGate i Entra ID (logowanie z nowego kraju).

## Etap 5 – Panel MVP – zakończony

- **Wcześniej (etapy 2–4):** logowanie i role, audyt, agenci i grupy, wdrażanie tokenem, wyszukiwarka zdarzeń, polityka archiwum, kanały powiadomień z filtrem alertów.
- **5a (09.10):** praca z alertami – filtry i licznik, przypisanie analityka, oś czasu (`gjallarhorn.alert_activity`) z notatkami, akcje zbiorcze, powiązane alerty, przejście do zdarzeń z okolicy alertu w Mímirze; automatyczne zamknięcia (powrót agenta) też na osi czasu.
- **5b (09.10):** burza alertów – limit osobnych powiadomień na regułę (5 w 10 min), nadwyżka wstrzymywana w outboxie i wysyłana jedną wiadomością zbiorczą; krytyczne i „rozwiązane” zawsze osobno.
- **5c (09.10):** reguły w panelu – historia wersji (`gjallarhorn.rule_versions`, różnice między wersjami), włączanie/wyłączanie z panelu (`rule_overrides`; wyłączenie z powodem i hasłem, detektor stosuje w 30 s), test reguły na zdarzeniach z ClickHouse z alertami, które by powstały (na danych laboratorium: spraying 1 alert / 35 zdarzeń, brute force 2 alerty – zgodnie z alertami #8–#10). Pakiety `detect` i `model` przeniesione do wspólnego `internal/`, semantyka progów w `detect` (jeden kod dla obu silników i testu).
- **5d (09.10):** Himinbjörg – strona „Stan systemu” (23 kontrole z Prometheusa z progami jak w Grafanie i podpowiedziami) oraz karty alertów i stanu systemu na stronie startowej.
- **5e (09.10) – kryterium etapu spełnione:** atak w laboratorium AD (password spraying i brute force ze stacji, PowerShell z zakodowanym poleceniem, nowe konto dodane do Backup Operators na DC i usunięte) → 6 alertów w kilka sekund (#16–#21) → powiadomienia na Discordzie zgodnie z filtrem kanału (od „średniego” – nowe konto jako „niskie” tylko w panelu) → analiza w panelu (powiązane alerty, Mímir, przypisanie, „w analizie”) → zamknięcie z powodem; całość na osi czasu alertów i w audycie. Poprawka po ćwiczeniu: instrukcje i opisy reguł składane w ciągłe akapity (bloki YAML łamały zdania na Discordzie).
- **Przesunięte:** tokeny deinstalacji agenta – do etapu 8 (ochrona agenta).

## Etap 6 – Kolektor syslog i dekodery – zakończony

- **6a (09.10):** `siem-collector` – agent w trybie kolektora (Linux, kontener na VM): syslog UDP/TCP z adresem nadawcy, ten sam bufor dyskowy, ponowienia, mTLS i heartbeat co agent Windows; rejestracja jednorazowym tokenem tworzonym na VM (`collector-enroll.sh`).
- **6b (09.10):** dekodery YAML (`internal/decode`): nagłówki RFC 3164 / 5424 / sam `<PRI>`, warunki `match` (w tym `host` i alternatywy `any`), parsery kv / json / csv / regex, mapowanie na pola ECS, wynik i czas zdarzenia, próbki. Wbudowane: FortiGate i MikroTik (RouterOS 6 i 7). Reguły Sigma z `product: fortigate` / `mikrotik`. Prawdziwy router użytkownika: RouterOS 7 nie wysyła tematów w nagłówku – dekoder poprawiony (rozpoznanie po tożsamości i treści, MAC adres nie jest już brany za nazwę programu), 10 nieudanych logowań przez Winbox → alert #27.
- **6c (09.10):** edytor dekoderów w panelu: lista w kolejności sprawdzania, test na wklejonych próbkach albo ostatnich nierozpoznanych wiadomościach (w pełnym zestawie – widać przesłonięcia), zapis z historią rewizji, wyłączenie / usunięcie z powodem i hasłem. Dostarczanie do normalizatorów przez NATS KV (`SIEM_DECODERS`) bez restartu, panel wyrównuje magazyn do bazy. Przy okazji: rezerwacje kolejek zajmowały cały `max_file_store` NATS – żaden nowy magazyn nie mógł powstać (limit podniesiony do 21 GB).
- **6d (09.10):** kwarantanna w panelu (grupy według źródła i powodu, oryginały) i ponowne przetwarzanie: panel → normalizator (NATS request-reply) → odzyskane zdarzenia w `SIEM_EVENTS` (zapis i detekcja, bez duplikatów w archiwum NIS2), wynik każdego wpisu w Sadze. Kwarantanna zapamiętuje adres nadawcy syslog.
- **6e (09.10):** symulator FortiGate (`tools/cmd/fortisim`) i reguły progowe: seria nieudanych logowań do VPN FortiGate, do panelu FortiGate i do routera MikroTik. Laboratorium: symulowane ataki → alerty #22–#26 w obu silnikach; test zgodności silników z korpusem syslog (155/155 trafień). Przerwa łączności kolektor–serwer: 50 wiadomości z bufora dotarło po przywróceniu `siem-ingest`.
- **Kryterium etapu (roadmapa):** logi FortiGate znormalizowane (symulator, wszystkie scenariusze), nowy dekoder utworzony w panelu przechodzi test na próbce. IIS (W3C) – parser `csv` z separatorem spacją go rozbiera, ale odczyt plików dziennika przez agenta to osobne źródło – przesunięte (razem z syslog po TLS).

## Etap 8 – ochrona agenta i skala – w toku

- **8a–8b (12.10): ochrona agenta (0.7.0)** – „utrudnić i wykryć”:
  - usługa z zawężonymi uprawnieniami: administrator nie zatrzyma ani nie usunie jej poleceniem `sc` czy `services.msc`; restart agenta to polecenie do usługi (kod 128), bez prawa zatrzymania;
  - jednorazowe tokeny deinstalacji z panelu (administrator, powód, hasło, audyt; na komputerze i w bazie tylko skrót) dla `siem_agent stop|upgrade|uninstall` i `msiexec /x … UNINSTALL_TOKEN=`;
  - agent co 30 s pilnuje uprawnień, typu uruchamiania i programu usługi (w menedżerze usług i w rejestrze), zmianę cofa i zgłasza;
  - dziennik zdarzeń ochrony w heartbeacie; ostatni heartbeat z powodem zatrzymania; wykrycie zabicia procesu (znacznik działania i czas startu systemu);
  - reguła wbudowana „Próba sabotażu agenta” – także zatrzymanie tokenem, którego panel nie wydał, i aktualizacja, po której agent nie wrócił;
  - ochrona przełączana w grupie agentów; stan i zdarzenia na stronie agenta.
  - **Laboratorium (DESKTOP-3P8VS81):** po aktualizacji przez MSI agent przeszedł na uprawnienia chronione bez fałszywego alarmu. `sc stop` → odmowa dostępu. Alerty #50–58: polecenia bez tokenu i ze złym tokenem, `sc sdset` (uprawnienia przywrócone w ciągu 30 s), `taskkill /f`, `sc sdset` + natychmiastowe `sc stop` (alert od razu, z ostatniego heartbeatu), `msiexec /x` bez tokenu (wycofane). Zatrzymanie, aktualizacja i deinstalacja MSI tokenem – bez alertu, token oznaczony jako użyty, ponowne użycie odrzucone.
  - Poprawka przy okazji: akcja MSI zatrzymująca agenta zainstalowanego bez MSI nie trafiała do instalatora (`wixl` nie obsługuje atrybutu `Directory`).
- **8c (12.10): skala – kalibracja na VM laboratoryjnej (4 vCPU, 10 GB), 3500 symulowanych agentów:**
  - pierwszy test (5000 zdarzeń/s, paczki co 2 s) – zaległość rosła bez końca; znalezione i poprawione:
    - writer: limit niepotwierdzonych wiadomości 1024 przy paczkach po kilka zdarzeń → ok. 2000 zdarzeń/s (teraz 16 384, writer ok. 7000/s);
    - korelacja „udane po nieudanych” przekraczała limit pamięci ClickHouse przy setkach nieudanych logowań na sekundę → liczenie w minutowych kubełkach z dokładnymi brzegami okna;
    - detektor: GC przy 200 MiB (stan progów kopiował pola klucza w każdym wpisie) → odchudzone wpisy, 768 MB;
    - zapis alertów: 4 polecenia SQL na trafienie (długi atak dołączany do jednego alertu obciążał PostgreSQL) → zapis zbiorczy;
    - silnik zapytań: kontekst progów porcjami po 500 kluczy (limit długości SQL) – przy dziesiątkach tysięcy kluczy przebieg się nie kończył, punkt kontrolny stał godzinami → klucze w tabeli zewnętrznej, jedno zapytanie; pobierał też niepotrzebnie surowy XML (200 MB);
    - przy 3500 agentach narzut na paczkę wysycał VM → **agent 0.7.1**: paczka poniżej 50 zdarzeń czeka do 10 s (serwery i DC bez zmian), zaległa paczka wysyłana przy zatrzymaniu;
  - po poprawkach: **5000 zdarzeń/s stabilnie** (kolejki ≈ 0, opóźnienie p99 2,5–6 s); **10 000/s** – VM wysycona, ale bez strat: 6 299 835 / 6 299 835 zdarzeń w bazie po 9 min nadrabiania;
  - koszt stosu ok. 0,6 rdzenia na 1000 zdarzeń/s (szacunek sprzętu: roadmapa, załącznik E);
  - **awaria w trakcie:** VM wyłączona przyciskiem w Proxmoxie (12:55) wróciła bez NATS i Prometheusa (Docker ich nie podniósł mimo `restart: unless-stopped`); przez 6 h potok restartował się w pętli, agenci buforowali – po uruchomieniu NATS wszystkie zdarzenia z przerwy dotarły. Poprawka: `boot.sh` z crontaba `@reboot` (`docker compose up -d`). Luka: nikt nie został powiadomiony (Prometheus też leżał) – do przeglądu etapu;
  - **masowy powrót po awarii serwera:** 3500 agentów, 5000 zdarzeń/s, ingest zatrzymany na 5 min (1,5 mln zdarzeń w buforach agentów). Po starcie ingest ginął z braku pamięci (OOM, 4 razy w 6 min: 256 MB, heartbeaty 3500 agentów bez limitu, do ~10 MB na paczkę w obsłudze), bufory agentów rosły dalej (2 mln). Poprawka: ingest 768 MB z `GOMEMLIMIT`, limit równoległych heartbeatów (`SIEM_INGEST_MAX_HEARTBEATS`, nadmiar → 429), NATS 1 GB. Po wdrożeniu w trakcie testu: ingest bez restartów przyjmował do 44 000 zdarzeń/s, bufory agentów puste po ok. 1,5 min, kolejka serwera po kolejnych 9 min; **4 652 542 / 4 652 542 zdarzeń w bazie**;
  - silnik zapytań: kontekst progów bez pełnych zdarzeń (klucz i wartość liczone w SQL) – wcześniej GC zajmował połowę czasu detektora;
  - **klucz sortowania `siem.events`** (wybrany wariant 1): `(event_dataset, toStartOfHour(ingested), host_name, timestamp, event_id)` zamiast `(event_dataset, host_name, timestamp, event_id)`. Silnik zapytań czytał w każdym przebiegu całą dzienną partycję (14,6 mln wierszy, 6,8 GB, ok. 25 s) – teraz najwyżej 80 tys. wierszy w ok. 130 ms. Migracja istniejącej tabeli: `clickhouse/events-order.sh` (writer zatrzymany, kopia partycjami z kontrolą liczby wierszy, atomowa zamiana; w laboratorium 12 s, bez zdarzeń generatora). Koszt: duplikat dosłany w innej godzinie przyjęcia nie jest scalany (wyszukiwanie go pomija);
  - sprzątanie po testach: 6286 alertów i 3500 agentów generatora usunięte, 50 alertów z ćwiczeń (etapy 4–8) zamkniętych z powodem „ćwiczenie”; zdarzenia generatora nie trafiają do archiwum Urd (`SIEM_ARCHIVE_EXCLUDE_AGENTS=agt-load-`), poza celowym testem archiwum (`agt-arch-`, 3,15 mln zdarzeń, do końca retencji). Skrypt `loadtest-cleanup.sh` – najpierw zdarzenia w ClickHouse, potem alerty (inaczej silnik zapytań odtwarzał je z tych samych danych);
  - **VM 8 vCPU (13.10):** 10 000 zdarzeń/s stabilnie (p99 3 s, 29% CPU wolne, bez swapu) – po podniesieniu pamięci writera (GC 50% CPU przy 400 MiB); 15 000/s wysyca VM, ale bez strat (9 455 168 / 9 455 168); archiwizator przy 10 000/s nadąża (ok. 120 B na zdarzenie, ok. 100 GB/dobę); generator urealniony (3500 kont, 0,2% nieudanych logowań; `-failures 5` – scenariusz ataku);
  - pomoc do pomiarów: `SIEM_PPROF=1` (profile Go na porcie metryk).

## Etap 7 – Entra ID i korelacja – zakończony (bez prawdziwego tenanta)

- **7a (12.10):** tożsamość osoby w każdym zdarzeniu (`user_identity`):
  - konto bez domeny, małymi literami – jeden klucz dla AD, Entra ID, VPN i routera;
  - konta techniczne bez osoby, także polskie nazwy (`ZARZĄDZANIE NT`), konta wirtualne i SID;
  - domeny organizacji i aliasy kont w panelu („Tożsamości”: osoby ze źródłami i kontami, podpowiedzi połączeń), dostarczane przez NATS KV;
  - pole `user.identity` w regułach i `identity:` w Mímirze;
  - laboratorium: `AZUJO\heimdall-lab` z DC i `heimdall-lab` z MikroTika to jedna osoba.
- **7b (12.10):** konektor `siem-connector` (Microsoft Graph: logowania i zmiany w katalogu):
  - kursor czasu z zakładką i nadrabianiem oknami, 429 z `Retry-After`, odnawianie tokenu;
  - identyfikator rekordu Graph jako identyfikator zdarzenia (bez duplikatów po restarcie);
  - wspólny szkielet z kolektorem;
  - symulator Graph (`entrasim`) z opóźnieniem logów, ograniczaniem zapytań i scenariuszami ataków.
  - Rejestracja agentów serwerowych jednym skryptem (`service-enroll.sh`). Poprawka przy okazji: `docker compose run` wczytywał resztę zdalnego skryptu.
- **7c (12.10):** dekodery `entra-signin` (`azure.signinlogs`) i `entra-audit` (`azure.auditlogs`):
  - źródła API bez nagłówka syslog;
  - stałe pola `set`, wynik `otherwise`, tablice JSON z indeksem;
  - `product: azure` w regułach.
  - Laboratorium: 40 rekordów z symulatora rozkodowanych, bez kwarantanny.
- **7d (12.10):** korelacje międzyźródłowe:
  - reguła Sigma „Password spraying z jednego adresu (wiele źródeł)” – próg `distinct user.identity`; test zgodności silników 169/169 z korpusem AD + Entra + VPN;
  - reguły wbudowane „Udane logowanie po serii nieudanych (wiele źródeł)” i „Logowanie z nowego kraju” – zapytania do ClickHouse co minutę, test na prawdziwym ClickHouse.
  - Przy okazji poprawiona reguła „Nowa usługa z podejrzanej lokalizacji” (fałszywe alarmy na aktualizacjach Defendera i agencie SIEM z konfiguracją w ProgramData).
- **7e (12.10) – ćwiczenie:**
  - spraying łącznie AD + Entra z adresu stacji: 4 konta w AD (`net use`) i 1 w Entra, osobno poniżej progu → alert #49;
  - spraying Entra + VPN → alert #37;
  - 12 prób na VPN FortiGate, potem udane logowanie do Entra tej samej osoby z tego adresu (Nigeria) → „Udane logowanie po serii nieudanych” (#41, źródła `azure.signinlogs, fortinet.fortigate`) i „Logowanie z nowego kraju” (#42).
- **Kryterium etapu (roadmapa):**
  - password spraying wykryty łącznie z AD i Entra – spełnione;
  - logowanie VPN i Entra powiązane z tą samą osobą – spełnione (osoba w zdarzeniach, korelacja);
  - zastrzeżenie: Entra z symulatora; konektor czeka na tenant z licencją P1/P2.
- **Przesunięte:** logi M365 (Management Activity API), lokalna baza GeoIP dla VPN.

## Test nocny (16/17.10.2026) – 8 h po poprawkach

7000 zdarzeń/s (3500 agentów, profil jak wyżej), ta sama VM (8 vCPU / 9,4 GB), po wyłączeniu ścieżki awaryjnej silnika zapytań, logów systemowych ClickHouse i z tabelą logowań dla korelacji:

- **201 807 747 zdarzeń wygenerowanych i przyjętych, 0 utraconych** (średnio 6991/s); 429 dla ok. 1,1% paczek przy chwilowych szczytach – agenci ponawiali, nic nie przepadło;
- **zapis nadążał przez całe 8 h**: zaległość writera zwykle poniżej 4000 wiadomości (szczyt 11 600), opóźnienie p99 zwykle 3–25 s (szczyt 51 s);
- **silnik zapytań nadążał**: opóźnienie stałe 2–5,5 min (poprzednio 2,5 h w tyle po 4 h); ClickHouse stale 1,3–3,8 rdzenia, bez wzrostu w czasie; korelacje czytają ułamek tego co wcześniej;
- **słaby punkt: VM na granicy mocy** – ok. 6,5–7 z 8 rdzeni zajęte (load 17–30), rosnące oczekiwanie na dysk (do 0,8 rdzenia, zajętość dysku 60–76%) przy scalaniu coraz większych części ClickHouse. Ustępuje detektor w locie: od ok. 3. godziny zaległość rosła o ok. 100 tys. zdarzeń na godzinę (na końcu 760 tys.); po zatrzymaniu ruchu przetwarzał 13 000/s – sam nie jest wolny, brakuje mu procesora;
- **korelacja na danych generatora**: generator rozkłada 0,2% nieudanych logowań równo na wszystkie 3500 kont, więc prawie każde konto ma 5 prób w 30 min i każde udane logowanie pasuje – 2506 alertów i ok. 8000 dołączanych trafień na minutę (2 mln wierszy `alert_events`), zapisywanych pod tą samą blokadą co trafienia detektora w locie. Profil nierealny, ale pokazuje, że otwarty alert korelacji dołącza każde kolejne udane logowanie;
- miejsce: ok. 125 B na zdarzenie w ClickHouse (z surowym XML), tabela logowań ok. 24 B na udane logowanie Windows;
- wniosek: na tej VM ok. 5000 zdarzeń/s z zapasem; 7000/s działa bez strat, ale detekcja w locie może po kilku godzinach być minuty w tyle.

## Test długotrwały (15.10.2026) – przerwany po 4 h 17 min

7000 zdarzeń/s (3500 agentów, realistyczny profil), VM 8 vCPU / 9,4 GB. Przerwany na prośbę (hałas serwera). Nic nie zginęło, ale **warunek „bez narastającego zalegania” nie jest spełniony**:

- przez pierwsze ok. 40 min wszystkie etapy nadążały (p99 3 s); potem ClickHouse urósł z 0,7 do 3–4 rdzeni, a zaległość writera i detektora rosła liniowo (na końcu ok. 285 tys. wiadomości, silnik zapytań 2,5 h w tyle);
- przyczyny (dziennik zapytań ClickHouse z czasu testu):
  1. **ścieżka awaryjna silnika zapytań** – przy błędzie łącznego zapytania (tu: przepełniona pamięć ClickHouse, 3,6 GB) sprawdzała każdą regułę osobnym pełnym skanem: 834 zapytania, **17 mld wierszy, 1 TB odczytu**, 62 nieudane przebiegi – pętla, która sama podtrzymywała przeciążenie. Poprawione: przy błędzie z braku zasobów przebieg kończy się od razu i ponawia za minutę;
  2. **korelacja „udane po nieudanych”** – co minutę czyta wszystkie zdarzenia Windows z ostatnich 1,5 h, żeby znaleźć nieudane logowania (ok. 48 mln wierszy, 13 s; razem 6,4 mld), plus pobieranie prób do osi alertu (3,5 mld). Koszt rósł z ruchem. Poprawione: tabela logowań `siem.auth_events` zasilana przy zapisie (widok zmaterializowany), korelacje czytają tylko ją – przy 1400 zdarzeń/s z 5% nieudanych ok. 117 tys. wierszy w 0,1 s;
  3. **logi systemowe ClickHouse 25.x** (`query_metric_log`, `processors_profile_log`) – scalanie `query_metric_log` zajmowało 2,2 GB pamięci. Wyłączone w `clickhouse/config.d/siem.xml`;
- sprzątanie: 107 mln zdarzeń testowych – mutacja DELETE przekraczała pamięć ClickHouse; partycja przepisana (7705 prawdziwych zdarzeń zachowanych, testowa reszta usunięta), konsument detektora utworzony od nowa (bez przerabiania 300 tys. wiadomości testowych).

## Przegląd etapu 8 (13.10.2026) – błędy i luki

| # | Pr. | Problem | Skutek | Stan |
|---|---|---|---|---|
| 1 | wysoki | Po wyłączeniu VM przyciskiem w Proxmoxie Docker nie podniósł NATS ani Prometheusa | 6 h bez potoku i bez powiadomienia: usługi restartowały się w pętli, panel i przekaźnik alertów (siem-api) też – brak NATS kończył API | Naprawione: start stosu przy uruchomieniu VM (`boot.sh`, sprawdzony przy resecie 12.10), alert Grafany „Potok zdarzeń nie działa” (sprawdzony: writer zatrzymany → wiadomość na Discordzie po ok. 6 min), API startuje bez NATS. Przyczyna po stronie Dockera nieznana |
| 2 | wysoki | Wąskie gardła przy 3500 agentach z małymi paczkami | Przy 5000 zdarzeń/s zaległość rosła bez końca | Naprawione w 8c: limit niepotwierdzonych wiadomości writera, korelacja w kubełkach, pamięć detektora i writera, zbiorczy zapis alertów, kontekst progów jednym zapytaniem, klucz sortowania zdarzeń, agent 0.7.1 (paczki do 10 s) |
| 3 | średni | Ingest ginął z braku pamięci przy masowym powrocie agentów | Każdy restart zrywał tysiące połączeń, bufory agentów rosły | Naprawione: 768 MB + `GOMEMLIMIT`, limit heartbeatów; po poprawce 44 000 zdarzeń/s przy powrocie |
| 4 | średni | Pierwsza wersja alertu „Potok zdarzeń nie działa” liczyła każdą przerwę z 3 min | Alarm przy każdym wdrożeniu | Naprawione przed użyciem: alarm, gdy usługa nie działała przez większość z 5 min |
| 5 | średni | Silnik zapytań przy długim, masowym ataku (setki nieudanych logowań na sekundę na tych samych kontach) | Każdy przebieg na nowo czyta kontekst „gorących” kluczy (do 15 mln wierszy) – silnik zostawał w tyle; PostgreSQL przekraczał pamięć współdzieloną | Złagodzone: przebieg do 100 000 zdarzeń, sprawdzanie znanych zdarzeń porcjami, `shm` Sagi 256 MB, detektor 1 GB. Zostaje: przy takim ataku silnik zapytań może być godzinę w tyle (alert Grafany po 15 min); silnik w locie wykrywa na bieżąco |
| 6 | uwaga | Limit kluczy progów w pamięci (200 000 zdarzeń) | Przy ataku z bardzo wielu adresów silnik w locie pomija część zdarzeń w progach (log, metryka) | Nadrabia silnik zapytań; limit chroni detektor przed brakiem pamięci |
| 7 | uwaga | Wspólna blokada zapisu alertów obu silników | Duży zapis silnika zapytań wstrzymuje na chwilę silnik w locie (zaobserwowane: pół minuty przy 10 000/s) | Później: osobne transakcje albo kolejka zapisu |
| 8 | uwaga | Testy skali bez archiwum (generator wykluczony z archiwizacji) | Archiwizator nie był obciążony | Sprawdzone osobno (`agt-arch-`, 10 000/s): nadąża. Plan dysku: ok. 100 GB/dobę przy 10 000 zdarzeń/s, ok. 3 TB na 30 dni |
| 9 | uwaga | Nowy klucz sortowania: duplikat dosłany w innej godzinie przyjęcia nie jest scalany | Liczniki (histogram) mogą policzyć zdarzenie dwa razy; wyszukiwanie je pomija | Do pamiętania |
| 10 | uwaga | Granica ochrony agenta | Administrator może zmienić uprawnienia usługi (`sc sdset`) i zatrzymać ją – zgłoszone jako sabotaż; zatrzymanie z konta SYSTEM traktowane jak instalator (alert dopiero, gdy agent nie wróci w 15 min); kolektor i konektor (kontenery Linux) bez ochrony | Opisane („utrudnić i wykryć”) |
| 11 | uwaga | Agent 0.7.1 trzyma małą paczkę do 10 s | Zdarzenie ze stacji o małym ruchu dociera do 8 s później | Świadomy koszt; serwery i DC bez zmian |
| 12 | uwaga | Sprzątanie po testach | Usunięte alerty wracały, bo zdarzenia testowe zostały w ClickHouse | `loadtest-cleanup.sh` (właściwa kolejność) |

## Przegląd etapu 7 (12.10.2026) – błędy i luki

| # | Pr. | Problem | Skutek | Stan |
|---|---|---|---|---|
| 1 | średni | Pomyłka w domenach organizacji (literówka, brak nazwy NetBIOS obok DNS) po cichu rozdziela tożsamości | W laboratorium `aazujo.centrala` i brak `azujo`: `test01` z AD stał się `azujo\test01`, osobno od `test01` z Entra – korelacje przestają łączyć osobę | Naprawione: panel pokazuje domeny kont widziane w zdarzeniach (zielone – na liście, pomarańczowe – poza nią, kliknięcie dodaje) i ostrzega na stronie Tożsamości |
| 2 | średni | Korelacji wbudowanych nie dało się wyłączyć z panelu (traktowane jak reguła systemowa) | Hałaśliwa korelacja tylko przez zmianę kodu | Naprawione: tryb „korelacja” – przełączanie jak reguły Sigma (powód, hasło, audyt) |
| 3 | średni | Konektor z błędem dostępu (zły sekret, brak zgody, brak licencji) wyglądał w panelu na zdrowego – heartbeat działał | Logi z chmury przestają płynąć niezauważone | Naprawione: stan kanału `entra-signin` / `entra-audit` w statusie agenta („brak dostępu” albo „błąd” z treścią) |
| 4 | niski | Po restarcie normalizator przez pierwsze sekundy stosował wbudowane dekodery i tożsamości bez ustawień z panelu | Pierwsze zdarzenia po restarcie z inną osobą albo zbiorem danych | Naprawione: start czeka na konfigurację z NATS (najwyżej 15 s) |
| 5 | niski | Eksport NIS2 bez osoby | Audytor nie łączy kont tej samej osoby | Naprawione: `user.identity` w NDJSON, kolumna `osoba` w CSV |
| 6 | uwaga | Wydajność korelacji (podzapytania ze zbioru udanych logowań) | – | Sprawdzone w laboratorium: ok. 50 ms i 30 tys. wierszy na przebieg (indeks po czasie przyjęcia) – bez zmian |
| 7 | uwaga | Konta lokalne urządzeń bez domeny (`admin` na MikroTiku i FortiGate) to ta sama osoba co domenowy „admin” | Możliwe łączenie niezwiązanych prób w korelacjach | Później: lista kont wspólnych (bez osoby albo z nazwą urządzenia) |
| 8 | uwaga | Graph v1.0 zwraca tylko logowania interaktywne; nieinteraktywne (tokeny aplikacji, odświeżanie sesji) są w API beta | Spraying przez stare protokoły bywa widoczny tylko w nieinteraktywnych | Później, przy prawdziwym tenancie |
| 9 | uwaga | „Powiązane alerty” szukają po koncie, nie po osobie | Alert z Entra (UPN) nie pokazuje alertów AD tej samej osoby | Później: osoba w alertach |
| 10 | uwaga | Scenariusze symulatora Graph cofają czas zdarzeń o ok. 2 min | W ćwiczeniu kolejność zdarzeń z różnych źródeł może się odwrócić (pierwsza próba #38) | Do pamiętania przy ćwiczeniach |

## Przegląd etapu 6 (09.10.2026) – błędy i luki

| # | Pr. | Problem | Skutek | Stan |
|---|---|---|---|---|
| 1 | średni | Eksport NIS2: czytnik `odczytaj.exe` pokazywał tylko dane z XML Windows; eksport gubił adres nadawcy syslog; archiwizator nie znał dekoderów z panelu | Audytor widział zdarzenia z urządzeń jako „bez rozpoznanego kodu”, bez treści i nadawcy; czytelna część eksportu inna niż w bazie | Naprawione: raport pokazuje treść, nadawcę, zbiór danych i akcję, nieudane logowania z urządzeń w „wymagających uwagi”; `log.source.address` w NDJSON i kolumny w CSV; archiwizator obserwuje dekodery (NATS KV) |
| 2 | średni | Kolektor: długość ramki TCP („octet counting”) czytana bez limitu | Strumień samych cyfr zajmował coraz więcej pamięci kolektora | Naprawione: najwyżej 7 cyfr, inaczej rozłączenie (test) |
| 3 | średni | Kolektor domyślnie przyjmuje syslog od wszystkich (syslog nie ma uwierzytelnienia) | Każdy w sieci mógł podsunąć wiadomości „z routera” | Laboratorium: lista dozwolonych sieci ustawiona; szablon konfiguracji zaleca `allow`. Uwierzytelnienie – syslog po TLS (później) |
| 4 | niski | Przycięte wiadomości syslog bez znacznika `truncated` (źródło i rdzeń agenta miały ten sam limit) | Nie było widać, że treść jest niepełna | Naprawione: znacznik i rozmiar oryginału z kolektora (także ramki TCP ponad limit) |
| 5 | niski | Pole `peer` w paczce bez walidacji | Dowolny tekst jako nadawca i nazwa hosta | Naprawione: ingest przyjmuje tylko adres IP |
| 6 | niski | `product` w regułach: silnik w locie porównywał zbiór danych bez wielkości liter, SQL – z; prefiks bez granicy (`fortinet.fortigatex`) | Możliwa rozbieżność silników przy własnych dekoderach | Naprawione: zbiory danych tylko małymi literami (walidacja dekodera), dopasowanie zbioru i jego podzbiorów w obu silnikach (test zgodności 155/155) |
| 7 | niski | Dekoder mógł użyć zbioru `windows.*` / `syslog.generic` i nadpisać pola systemowe (`syslog.*`, `decoder.*`, `siem.*`) – także z treści wiadomości | Zdarzenia syslog mogły uruchamiać reguły Windows albo podszyć się pod znacznik ponownego przetworzenia | Naprawione: zbiory zarezerwowane, pola systemowe chronione (test) |
| 8 | niski | Synchronizacja NATS KV co 5 min zapisywała wszystkie dekodery | Normalizatory przeładowywały dekodery co 5 min | Naprawione: zapis tylko zmienionych |
| 9 | niski | Nagłówek RFC 3164 bez nazwy hosta („sshd[812]: …”) – znacznik brany za host | Zły `host.name`, brak nazwy programu | Naprawione (test) |
| 10 | niski | Test dekodera z próbkami z bazy używał jednego adresu nadawcy | Dekodery z warunkiem `peer` wyglądały na niepasujące | Naprawione: adres uzupełniany, gdy próbki są od jednego nadawcy; ostrzeżenie przy wielu |
| 11 | niski | Zapytania kwarantanny bez testu na ClickHouse (filtr wskazanych wpisów nieużywany w UI) | Ryzyko błędu dopiero w produkcji | Naprawione: test na danych laboratorium |
| 12 | uwaga | Grupy kwarantanny liczą także wpisy odzyskane | Licznik nie maleje po ponownym przetworzeniu | Opisane w nagłówku kolumny; stan wpisów na liście i w zleceniach |
| 13 | uwaga | Licznik `{{count}}` w instrukcji alertu progowego z chwili przekroczenia progu (#27: „5” przy 10 zdarzeniach) | Instrukcja zaniża skalę trwającej serii | Bez zmian (od etapu 4) – liczba zdarzeń jest w alercie |
| 14 | uwaga | Każdy zarejestrowany agent może wysłać zdarzenia „syslog:” (jak dowolny XML Windows) | Przejęta stacja może fałszować logi urządzeń | Do etapu 8 (ograniczenie źródeł do typu agenta) |
| 15 | uwaga | Utrata kolektora albo cisza urządzenia nie wywołuje alertu, gdy kolektor jest w grupie bez progu utraty łączności | Logi z sieci mogą przestać płynąć niezauważone | Zalecenie: osobna grupa „Kolektory” z alarmem po utracie łączności; reguła „cisza źródła” – później |

## Przegląd etapu 5 (09.10.2026) – błędy i luki

| # | Pr. | Problem | Skutek | Stan |
|---|---|---|---|---|
| 1 | Ś | Brak retencji alertów: `alert_events` ma wiersz na każde trafienie, outbox i oś czasu rosną bez końca | przy zalewie zdarzeń (np. 100 nieudanych logowań/s) setki tysięcy wierszy na jeden alert; baza Saga rośnie bez limitu | **naprawione:** detektor co 6 h usuwa alerty zamknięte dawniej niż `SIEM_ALERT_RETENTION_DAYS` (domyślnie 365, 0 = bez usuwania) razem z ich zdarzeniami i osią czasu, oraz wysłane powiadomienia starsze niż 30 dni; paczkami, otwarte alerty zostają zawsze |
| 2 | Ś | Zamknięcie wielu alertów naraz mogło się zakleszczyć z detektorem dopisującym trafienia do tych samych alertów | PostgreSQL przerywa jedną transakcję – w panelu „błąd wewnętrzny” | **naprawione:** transakcje triage ponawiane do 3 razy po zakleszczeniu |
| 3 | Ś | Test reguły bez limitu | analityk klikający „Przetestuj” (zapytanie nawet za 7 dni) mógł obciążyć ClickHouse | **naprawione:** najwyżej 2 testy naraz, nadmiar – „spróbuj za chwilę” |
| 4 | N | Alert password spraying pokazywał konto z pierwszego zdarzenia („anna.kowalska”) | mylące – alert dotyczy wielu kont | **naprawione:** alerty progu „różnych wartości” bez konta (lista kont w opisie) |
| 5 | N | Stan systemu: przy samym silniku zapytań „0 reguł w locie” jako ostrzeżenie | fałszywe ostrzeżenie | **naprawione:** „Włączone reguły” z obu silników |
| 6 | N | Lista alertów: odświeżanie co 15 s wracało do pierwszych 100 | doładowane starsze alerty i zaznaczenia znikały | **naprawione:** po doładowaniu starszych odświeżanie wstrzymane |
| 7 | N | Instrukcje reguł łamały się w środku zdania (bloki YAML) | nieczytelne wiadomości na Discordzie | **naprawione w 5e** |
| 8 | N | Bardzo hałaśliwa reguła nadal daje 5 osobnych wiadomości co 10 min + wiadomość zbiorczą | przy wielogodzinnej burzy – kilkadziesiąt wiadomości na godzinę | do decyzji: wyciszenie reguły w panelu albo dłuższe okno (`SIEM_ALERT_NOTIFY_WINDOW`) |
| 9 | N | Alert przypisany do konta, które potem usunięto | przypisanie wskazuje nieistniejącego analityka | do poprawy przy zarządzaniu kontami (np. zdjęcie przypisań przy usuwaniu konta) |

**Sprawdzone i w porządku:** uprawnienia nowych akcji (przypisanie, notatki, akcje zbiorcze – analityk; wyłączenie reguły – administrator, powód i hasło; stan systemu i wersje – podgląd), ochrona CSRF i ścisłe dekodowanie żądań, kompilacja reguł z panelu do SQL (escapowanie literałów, limity konta `siem_panel`), kolejność i jednokrotność powiadomień (rezerwacja w outboxie, sortowanie), samokontrola detektora (zwolnienie blokady przy wyjściu procesu).

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
| 10 | Ś | Burza alertów: każdy alert to osobna wiadomość (Discord przyjmuje ok. 30/min) | przy hałaśliwej regule kanał zalany, ważne alerty giną w tłumie | **zrobione 09.10 (5b):** limit na regułę i wiadomość zbiorcza |
| 11 | Ś | Lista alertów w panelu: najnowsze 100, bez stronicowania | starsze otwarte alerty widać tylko filtrami | **nieaktualne** – lista ma doładowywanie starszych; w 5a doszły filtry i licznik |
| 12 | Ś | Jeden detektor (blokada w Sadze) – brak drugiej kopii w gotowości | restart/awaria = przerwa w detekcji (zdarzenia czekają w kolejce, nic nie ginie; alert Grafany po 3 min) | **zrobione 09.10:** samokontrola – zawieszona pętla kończy proces, Docker go podnosi (stan z Sagi); druga kopia w gotowości ma sens dopiero na drugim hoście (mechanizm blokady już ją obsługuje) – przy skalowaniu |
| 13 | N | Powrót agenta zamyka alert utraty łączności bez powiadomienia | analityk nie wie z Discorda, że problem minął | **zrobione 09.10:** opcja grupy „Powiadamiaj także o powrocie” – wiadomość „[ROZWIĄZANY]” z długością przerwy; do tego filtr alertów w każdym kanale (poziom, reguły) |
| 14 | N | W tabeli agentów jest 50 nieaktywnych wpisów (symulacje z etapu 2) | po ustawieniu progu w grupie domyślnej każdy da alert utraty łączności | **zrobione 09.10:** 50 agentów `agt-load-*` usuniętych (wpisy w audycie) |
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
