# Historia zmian

Vardr wychodzi w wydaniach (aktualizacjach). Tu jest to, co zmienia się między nimi – dla administratora, który aktualizuje serwer: nowe funkcje, zmiany zachowania i to, co trzeba zrobić przy aktualizacji. Format według [Keep a Changelog](https://keepachangelog.com/pl/1.1.0/), numery wersji według [SemVer](https://semver.org/lang/pl/). Aktualizacja serwera: [docs/instalacja.md](docs/instalacja.md) ([English](docs/en/installation.md#upgrade)).

## [1.8.0] – 2026-10-29 – Agent Linux, auditd i poprawki bezpieczeństwa

### Dodane
- **Agent Linux** ([docs/agent.md](docs/agent.md#agent-linux-od-wersji-011)): `vardr-agent` 0.11 dla Linuksa z systemd (amd64, arm64) – instalacja `sudo ./vardr-agent install -server … -token …` (usługa `vardr-agent.service`, pliki w `/etc/vardr-agent` i `/var/lib/vardr-agent`), te same polecenia, rejestracja tokenem, bufor dyskowy, heartbeat i limity grupy co agent Windows. Źródło: dziennik systemd (uwierzytelnianie i ostrzeżenia, dodatkowe jednostki i programy) wysyłany jako syslog – działają wbudowany dekoder i reguły Linuksa. Ochrona jak w Windows (grupa agentów): `systemctl stop` odmawia (drop-in `RefuseManualStop`), zatrzymanie, aktualizacja i deinstalacja tylko tokenem z panelu; `kill`, zabicie procesu, zmiany usługi i próby bez tokenu trafiają do panelu jako alert.
- **auditd na agencie Linux** ([docs/agent.md](docs/agent.md#agent-linux-od-wersji-011)): źródło `auditd` (dziennik `/var/log/audit/audit.log` z rotacją, rekordy zdarzenia zgrupowane), nowy parser dekoderów `audit` i wbudowany dekoder `linux-audit` (zbiór `linux.audit`: uruchomione programy z argumentami, logowania, sudo, zmiany kont, zmiany konfiguracji audytu, klucze reguł), Sigma `product: linux` z `service: auditd` i `category: process_creation`, zalecane reguły audytu (`vardr-agent audit-rules`) i 8 reguł detekcji: wyłączenie audytu, ręczna zmiana plików kont, zmiana sudoers, klucze SSH roota i sshd_config, cron/systemd/ld.so.preload, moduł jądra, odwrócona powłoka, program z /tmp.
- **Pliki logów na agencie Linux** ([docs/agent.md](docs/agent.md#agent-linux-od-wersji-011)): sekcja `files:` – dowolne pliki tekstowe wiersz po wierszu (wzorce `*.log`, rotacja logrotate i copytruncate, wznowienie bez duplikatów), wysyłane jako syslog z nazwą programu `app`, więc działają dekodery z panelu dopasowane po programie; bez dekodera – `syslog.generic`.
- **Usługa czasu na agencie Linux**: agent zgłasza stan synchronizacji czasu (systemd-timesyncd, chrony, ntpd) – w szczegółach agenta zamiast „unknown”.
- **Paczka agenta Linux w panelu** ([docs/agent.md](docs/agent.md#agent-linux-od-wersji-011)): Bifröst przy tokenie wydaje paczkę tar.gz dla amd64 albo arm64 (program, CA, adres serwera, token, `install.sh` – instalacja `sudo ./install.sh`) i pokazuje polecenie do wdrożenia masowego (Ansible, skrypt); `deploy.sh agent` buduje też programy Linux do `agent-dist/`.

### Poprawione
- Dekoder `linux`: komunikaty systemd-logind 256+ z nazwami w apostrofach (`New session '42' of user 'jan'`) – konto bez apostrofów.
- **Silnik zapytań stawał przy wielu włączonych regułach**: wszystkie reguły szły jednym zapytaniem do ClickHouse, które po włączeniu ok. 120 reguł Sigmy przekraczało limit długości zapytania (256 KB) – każdy przebieg kończył się błędem, a zaległość (korelacje, progi) rosła bez końca. Reguły idą teraz porcjami (do 64 KB warunków na zapytanie) na wspólnym zakresie zdarzeń; aktualizacja detektora nadrabia zaległość sama.
- Agent: przy niepoprawnym tokenie deinstalacji (np. wygenerowanym dla innego agenta o tej samej nazwie komputera) komunikat podaje identyfikator agenta.

### Bezpieczeństwo
- **Go 1.27.3**: wszystkie programy (serwer, panel, agenci) budowane poprawioną wersją Go (`toolchain` w `go.mod`) – 11 podatności biblioteki standardowej w 1.27.0 (HTTP/2, TLS, x509, nagłówki MIME), z których korzysta kod Vardr.
- **Klucz API asystenta AI zaszyfrowany w bazie** (AES-GCM kluczem MFA, jak sekret SSO i hasło konta LDAP); klucz zapisany wcześniej otwartym tekstem jest szyfrowany przy pierwszym odczycie. Zmiana klucza MFA wymaga ponownego wpisania klucza API.
- **Skanowanie podatności w CI**: `govulncheck` (Linux i Windows) i `npm audit` (wysokie i krytyczne przerywają CI), także co tydzień bez zmian w kodzie; w repozytorium włączone alerty i poprawki Dependabota, skanowanie sekretów i blokada wypchnięcia sekretu.
- **Reguły a SQL**: test rozmyty kompilatora reguł (wartości i nazwy pól nie zmieniają struktury zapytania ClickHouse, także w CI) i test literałów na prawdziwym ClickHouse.

### Aktualizacja
- Serwer: paczka instalacyjna jak zwykle (`sudo ./install.sh`), bez migracji baz. Paczka zawiera programy agenta Linux (amd64, arm64) dla Bifröst.
- Agent Windows 0.11.0 – w grupach z automatycznymi aktualizacjami sam, pozostałe przez MSI (Huginn → „Pobierz aktualizację agenta (MSI)”, GPO).
- Agent Linux 0.11.0 – nowy: paczka tar.gz z tokenem w Bifröst, instalacja `sudo ./install.sh`; zalecany auditd z regułami `vardr-agent audit-rules`.
- Klucz API asystenta AI zapisany wcześniej otwartym tekstem szyfruje się sam przy pierwszym odczycie ustawień.

## [1.7.0] – 2026-10-27 – Aktualizacje agentów, archiwum w S3, syslog TLS, IIS i klucze bezpieczeństwa

### Dodane
- **Automatyczne aktualizacje agenta Windows** ([docs/agent.md](docs/agent.md#automatyczne-aktualizacje-od-wersji-010)): opcja grupy agentów (domyślnie wyłączona, włączenie potwierdzane hasłem). Agent 0.10+ starszy niż instalator na serwerze pobiera go z panelu przez mTLS w ciągu 30 minut (losowo), sprawdza sumę SHA-256 i uruchamia `msiexec`; bez obniżania wersji, nieudana próba powtarzana po 6 godzinach. Stan aktualizacji na stronie agenta.
- Agent Windows **0.10.0**.
- **Retencja zdarzeń per zbiór** ([docs/operacje.md](docs/operacje.md#retencja)): `SIEM_EVENTS_TTL_DATASETS` (np. `fortigate.=3,windows.security=30` – prefiks `event.dataset` = dni) obok `SIEM_EVENTS_TTL_DAYS`; instalator stosuje ją przy aktualizacji, `clickhouse/retention.sh` od ręki.
- **Kopia archiwum NIS2 w S3 z Object Lock** ([docs/instalacja.md](docs/instalacja.md#kopia-archiwum-w-s3)): archiwizator wysyła każdą zamkniętą godzinę (segmenty i manifest) do kubełka z blokadą obiektów w trybie COMPLIANCE do końca retencji – kopii nie da się usunąć ani nadpisać nawet po przejęciu serwera i konta magazynu. AWS S3, Wasabi, Backblaze B2, MinIO, Ceph. Włączana zmiennymi `SIEM_ARCHIVE_S3_*`; stan w *Stanie systemu* („Kopia w S3 (Object Lock)”).
- **Syslog przez TLS** ([docs/dekodery.md](docs/dekodery.md#syslog-przez-tls)): kolektor przyjmuje syslog przez TLS (RFC 5425, port 6514) obok UDP/TCP, opcjonalnie tylko od urządzeń z certyfikatem wystawionym przez wskazane CA (i o nazwie z listy). Certyfikat kolektora tworzy `siem-collector tls-cert`. Port 6514 wystawiony w `docker-compose.yml`.
- **Logi IIS** ([docs/agent.md](docs/agent.md#logi-iis-od-wersji-010)): agent Windows 0.10 czyta dzienniki IIS w formacie W3C (każda witryna osobnym kanałem, pozycja zapisywana jak dla dzienników Windows), włączane opcją grupy *Logi IIS* albo w `agent.yaml`. Wbudowany dekoder `iis` (zbiór `iis.access`), produkt w regułach `iis` oraz `category: webserver` Sigmy.
- **Klucze bezpieczeństwa i passkeys (WebAuthn)** ([docs/panel.md](docs/panel.md#klucze-bezpieczeństwa-i-passkeys-webauthn)): logowanie do panelu dotknięciem klucza (YubiKey, Windows Hello, Touch ID, passkey) zamiast kodu z aplikacji – odporne na phishing. Klucze dodaje się w *Moje konto → Bezpieczeństwo konta* (hasło, do 10 na konto); aplikacja TOTP i kody zapasowe zostają drogą awaryjną. Wymaga panelu otwieranego po nazwie (nie po adresie IP) przez HTTPS.
- **Własny zakres czasu w Mímirze**: obok gotowych zakresów (15 min – 7 dni) przycisk *Własny zakres* – początek i koniec wpisane ręcznie (do 31 dni); zakres trafia do adresu strony, więc link można przekazać dalej.

### Aktualizacja
- Pierwsza aktualizacja agentów do 0.10.0 – ręcznie (MSI, GPO); kolejne mogą już przychodzić automatycznie.
- Migracja spisu archiwum `012_offsite.sql` (wykonuje ją siem-archiver przy starcie) i bazy panelu `030_webauthn.sql` (siem-api).

## [1.6.0] – 2026-10-27 – Wydania na GitHubie, SSO Entra ID i nowe źródła syslog

### Dodane
- **Wydania na GitHubie z tagu** ([docs/rozwoj.md](docs/rozwoj.md#wydania)): paczka instalacyjna serwera, `vardr-mcp.exe`, `odczytaj.exe` i `SHA256SUMS` budowane przez GitHub Actions, opis wydania z CHANGELOG. Szybki start w README i instrukcja instalacji zaczynają się od pobrania paczki z wydania i sprawdzenia sumy.
- **Podpisywanie programów Windows** (Authenticode, Azure Artifact Signing) w wydaniu – `vardr-agent.exe`, `vardr-mcp.exe`, `odczytaj.exe`; włączane zmienną repozytorium `SIGNING=true` po skonfigurowaniu konta podpisywania. Podpisany agent trafia też do paczki serwera.
- **Logowanie SSO przez Microsoft Entra ID** ([docs/panel.md](docs/panel.md#logowanie-sso-microsoft-entra-id)): przycisk na stronie logowania (OpenID Connect z PKCE), ustawienia w *Administracja → Logowanie SSO* (aplikacja w Entra ID, sekret zaszyfrowany, powiązania grupa → profil w kolejności). Konto panelu powstaje przy pierwszym logowaniu i jest wiązane po identyfikatorze Entra ID; profil wynika z grup przy każdym logowaniu. Drugi składnik zapewnia Entra ID (dostęp warunkowy) – gdy polityka MFA panelu obejmuje konto, wymagany jest `amr` = `mfa` w tokenie. Konta SSO nie mają hasła w panelu: operacje chronione hasłem potwierdzają przyciskiem *Potwierdź w Entra ID* (okienko z ponownym logowaniem). Konta lokalne, w tym awaryjne konto administratora, działają bez zmian.
- **Nowe źródła syslog z dekoderem wbudowanym** ([docs/dekodery.md](docs/dekodery.md#źródła-z-dekoderem-wbudowanym)): serwery **Linux** przez rsyslog (logowania SSH, sudo, su, PAM, zmiany kont i grup), **pfSense i OPNsense** (zapora filterlog IPv4/IPv6, logowania do panelu) oraz **Cisco ASA / Firepower** (listy dostępu, logowania administratorów, AAA, sesje VPN AnyConnect, polecenia; numer komunikatu w `event.code`). Konfiguracja urządzeń w dokumentacji. Produkty w regułach: `linux`, `pfsense` (`opnsense`), `cisco` (`asa`).
- **Reguły dla nowych źródeł**: Linux – seria nieudanych logowań SSH, próby na wiele nieistniejących kont, logowanie SSH na root, założenie konta, dodanie do grupy uprzywilejowanej (sudo, wheel, docker…), odmowa sudo; pfSense/OPNsense – skanowanie portów, seria nieudanych logowań do panelu; Cisco ASA – seria odrzuconych logowań VPN, logowań administratora, skanowanie portów.
- Logowania z Linuksa, pfSense/OPNsense i Cisco ASA (także połączenia VPN) liczą się w korelacji „udane logowanie po serii nieudanych” i w tabeli logowań.
- **Stan systemu: „Nieczytelne paczki (24 h)”** – paczki, których normalizator nie odczytał (uszkodzone); ich oryginał zostaje w archiwum NIS2.
- **Zapora** ([docs/instalacja.md](docs/instalacja.md#zapora)): które sieci potrzebują których portów i jak je ograniczyć (łańcuch DOCKER-USER – Docker omija ufw i firewalld). Nowa zmienna `VARDR_GRAFANA_ADDR` – np. `127.0.0.1`, żeby Grafana była dostępna tylko tunelem SSH.

### Zmienione
- `deploy/vardr/build-bundle.sh` przyjmuje gotowe programy Windows (`VARDR_WINDOWS_BIN`) zamiast budować je samodzielnie.

### Aktualizacja
- Migracja bazy panelu `029_oidc.sql` (wykonuje ją siem-api przy starcie). Logowanie SSO jest wyłączone, dopóki administrator go nie skonfiguruje; wymaga klucza `certs/mfa.key`.
- Instalator przy aktualizacji odświeża widok tabeli logowań w ClickHouse (`03-auth-events.sh`) – nowe źródła logowań działają bez ręcznych kroków. Zaktualizuj normalizator (nowe dekodery) i detektor (nowe produkty reguł) razem.

## [1.5.3] – 2026-10-27 – Wyjątki reguł i propozycje AI

### Dodane
- **Wyjątki reguł** ([docs/reguly.md](docs/reguly.md#wyjątki)): warunek (pola z modyfikatorami jak w selekcji Sigmy), przy którym reguła nie trafia – na powtarzalne fałszywe alarmy zamiast wyłączania całej reguły. Zakładka *Wyjątki* w szczegółach reguły i *Dodaj wyjątek reguły* na stronie alertu (pola zdarzenia do wyboru). Przed zapisem *Sprawdź na historii* – ile trafień z ostatnich 7 dni wyjątek ukryje, z przykładami. Powód, hasło, opcjonalne wygaśnięcie (domyślnie 90 dni), audyt; działa w obu silnikach w ciągu 30 s, test reguły uwzględnia wyjątki, lista reguł pokazuje ich liczbę.
- **Propozycje wyjątków od asystenta AI** – narzędzie `fp_candidates` (asystent i serwer MCP): reguły z alertami zamkniętymi jako fałszywy alarm albo uzasadnione działanie, z najczęstszymi komputerami, kontami i przykładami. Asystent (czat albo „Analiza AI” alertu) proponuje wąski wyjątek; przycisk *Utwórz wyjątek* otwiera formularz z propozycją – zapisuje człowiek, po sprawdzeniu na historii.
- **Propozycje reguł od asystenta AI** – nowa reguła Sigmy (np. dla techniki ATT&CK bez wykrywania) z przyciskiem *Przetestuj i zapisz jako próbną*: test na zdarzeniach i zapis w panelu od razu w trybie próbnym (trafienia bez alertów).
- **Pojedyncze reguły Sigmy zapisywane w panelu** (dotąd tylko korelacje z kreatora), opcjonalnie od razu w trybie próbnym.

### Aktualizacja
- Migracja bazy detekcji `015_rule_exceptions.sql` (wykonuje ją siem-detector) – zaktualizuj detektor przed siem-api.
- Nowe narzędzie `fp_candidates` w serwerze MCP – pobierz nowy `vardr-mcp.exe` z panelu (*Dostęp AI*), jeśli używasz MCP na komputerze analityka.

## [1.5.2] – 2026-10-27 – Analiza AI incydentu i propozycje NIS2

### Dodane
- **Analiza AI incydentu** ([docs/panel.md](docs/panel.md#asystent-ai-w-panelu)): przycisk „Analiza AI” na stronie incydentu (przebieg, zakres i skutki, IoC, przyczyna, zalecane działania, otwarte pytania), zapis przy incydencie jak przy alercie. Wymaga grupy *incydenty* w polityce AI.
- **Propozycje AI do zgłoszenia NIS2** – analiza incydentu proponuje treść pól: opis, skutki, IoC, przyczyna, środki ograniczające. Analityk wstawia wybrane do formularza ustaleń, poprawia i zapisuje; na osi czasu zostaje wpis o użyciu propozycji AI (analiza, model). Szkic zgłoszenia powstaje z pól incydentu – AI nie pisze zgłoszenia samo.

### Aktualizacja
- Migracja bazy panelu `028_ai_analyses.sql` – wspólna tabela analiz AI alertów i incydentów; analizy z 1.5.x przenoszone automatycznie.

## [1.5.1] – 2026-10-27 – Poprawki bezpieczeństwa asystenta AI

### Bezpieczeństwo
- **Połączenia asystenta z endpointem modelu** (CodeQL `go/request-forgery`): zapisany klucz API idzie tylko pod zapisany adres – „Sprawdź i pobierz modele” z innym adresem nie wyśle go bez potwierdzenia hasłem; przy błędzie sprawdzania panel pokazuje tylko kod HTTP, bez treści odpowiedzi; odmowa połączeń z adresami lokalnymi łącza (169.254.0.0/16 – metadane chmury, fe80::/10), rozgłoszeniowymi i nieokreślonymi, sprawdzana po rozwiązaniu nazwy (także przy DNS rebinding). Adres endpointu ustawia administrator, więc alert dotyczył funkcji zamierzonej; sieć lokalna i localhost pozostają dozwolone dla modeli lokalnych.

### Zmienione
- **Analizy AI przy alercie widzą tylko osoby z uprawnieniem „asystent AI”** (dotąd – każdy z odczytem alertów): wnioski modelu mogą opierać się na danych, do których inni nie mają dostępu. Usunięcie analizy – „asystent AI” i zmiana alertów.

## [1.5.0] – 2026-10-27 – Asystent AI

### Dodane
- **Asystent AI w panelu** ([docs/panel.md](docs/panel.md#asystent-ai-w-panelu)): przycisk „Analiza AI” na stronie alertu i czat „Zapytaj Vardra” w nagłówku. Serwer łączy się z modelem przez API zgodne z OpenAI (LM Studio, Ollama, vLLM, usługa w chmurze); model korzysta z narzędzi MCP tylko do odczytu, z uprawnieniami zalogowanego analityka zawężonymi przez politykę AI (narzędzia, zakres, maskowanie). Odpowiedzi z odnośnikami do źródeł (alert, zapytanie), postęp na żywo (wywoływane narzędzia), przerwanie, kontynuacja rozmowy. Limity: kroki, czas, długość wyniku narzędzia, pytania dziennie na osobę, równoczesne pytania; każde pytanie w audycie (`ai_assistant_used`).
- **Analiza AI zapisana przy alercie** – wynik „Analizy AI” zostaje na stronie alertu (karta *Analiza AI*: kto, kiedy, model; wcześniejsze analizy do wyboru, „Analizuj ponownie”); widzi ją każdy z odczytem alertów, usunąć może osoba ze zmianą alertów (wpis w audycie). Dalsze pytania w czacie nie są zapisywane.
- **Korelacja alertów** – narzędzie `correlate_alerts` (asystent w panelu i serwer MCP): grupy alertów połączonych wspólnym komputerem, kontem (osobą) albo adresem IP, ze wspólnymi cechami, regułami i czasem; reguły na wielu komputerach i cechy zbyt częste, by łączyć (np. serwer centralny). Grupy liczy serwer (do 300 alertów), model je interpretuje i sprawdza. W pustym czacie – przykładowe pytania.
- **Dokumentacja Vardra dla AI** – narzędzie `search_docs` (asystent w panelu i serwer MCP, przy włączonej polityce AI niezależnie od grup narzędzi): wyszukiwanie w dokumentacji wbudowanej w siem-api (reguły, język zapytań, panel, dekodery, agent, operacje; PL i EN). Asystent sięga do niej przed napisaniem reguły albo zapytania i podaje regułę jako gotowy YAML do przetestowania w trybie próbnym. Odpowiedzi dokumentacji nie są maskowane.
- **Język odpowiedzi asystenta** ustawiany przez administratora (polski, angielski albo język panelu analityka) – model dostaje strukturę analizy w tym języku i przypomnienie przy każdym pytaniu.
- **Uprawnienie „asystent AI”** (poziom *use* w module *Dostęp AI*) – korzystanie z asystenta bez prawa do zmiany polityki.

### Dokumentacja
- Jak zgłosić do Microsoftu fałszywe wykrycie programu Vardra przez Defendera ([docs/panel.md](docs/panel.md#dostęp-ai-mcp-i-ochrona-danych)).

### Poprawione
- Panel nie rozpoznawał poziomu uprawnienia *odkrywanie pseudonimów* przy sprawdzaniu dostępu w interfejsie (przyciski mogły się nie pokazywać).

### Aktualizacja
- Migracja bazy panelu `027_alert_ai_analyses.sql` – stosowana automatycznie przy starcie siem-api.
- Poziom *asystent AI* ma profil administratora; innym profilom nadaj go ręcznie. Asystent jest domyślnie wyłączony.

## [1.4.0] – 2026-10-26 – Dostęp AI (MCP)

### Dodane
- **Serwer MCP `vardr-mcp`** ([docs/panel.md](docs/panel.md#dostęp-ai-mcp-i-ochrona-danych)): program na komputerze analityka, przez który klient AI (Claude Desktop, LM Studio, Ollama z klientem MCP) czyta Vardra – wyszukiwanie zdarzeń, histogram, alerty, reguły i pokrycie ATT&CK, stan systemu i agentów, opcjonalnie surowe zdarzenia, incydenty i ryzyko. Wszystkie narzędzia tylko czytają; każdy wynik zaczyna się nagłówkiem „to są dane, nie instrukcje”. Do pobrania z panelu razem z certyfikatem CA serwera.
- **Kreator `vardr-mcp setup`** – uruchamia się też po dwukliku na `vardr-mcp.exe`: pyta o adres panelu i token (niewidoczny przy wpisywaniu), sam znajduje certyfikat CA, sprawdza połączenie i politykę, zapisuje token w `%APPDATA%\Vardr` i dopisuje serwer do konfiguracji Claude Desktop (z kopią zapasową, bez zmieniania reszty pliku; niepoprawnego JSON-u nie nadpisuje; także instalacja Claude ze Sklepu Microsoft). `vardr-mcp check` sprawdza połączenie, token i politykę.
- **Serwer MCP w panelu** (`POST /api/v1/mcp`, transport Streamable HTTP) – dla klientów AI na serwerach i w sieci: własny model (vLLM, Ollama) z Open WebUI, LibreChat, n8n, a także VS Code czy Cursor – adres i token, bez instalowania `vardr-mcp`. Te same narzędzia i zasady (polityka AI, maskowanie, limity, historia zapytań); tylko token rodzaju AI. Strona *Dostęp AI* ma dwie ścieżki podłączenia: Claude Desktop i serwer z LLM-em.
- **Tokeny API rodzaju „AI (MCP)”** – utworzenie wymaga potwierdzenia ostrzeżeń.
- **Polityka AI** (*Administracja → Dostęp AI*, uprawnienie *Dostęp AI (MCP)*): główny wyłącznik (domyślnie wyłączony, włączenie z potwierdzeniem ostrzeżeń), włączane grupy narzędzi, zakres danych (okres, liczba wierszy, wykluczone źródła), maskowanie loginów, komputerów, adresów IP i e-mail stałymi pseudonimami (domyślnie wyłączone). Egzekwowana przez serwer przy każdym zapytaniu tokenem AI – także z pominięciem `vardr-mcp`; każde zapytanie spoza włączonych narzędzi i każda zmiana – odmowa i wpis w audycie.
- **Odkrywanie pseudonimów** (uprawnienie *odkrywanie pseudonimów*, z powodem i wpisem w audycie) i **historia zapytań AI**.
- **Ostrzeżenia i lista do uzgodnienia z IOD**: RODO, przekazanie danych do modelu zewnętrznego, halucynacje, prompt injection, zakaz decyzji wyłącznie automatycznych (art. 22 RODO) – w panelu i w dokumentacji.

### Aktualizacja
- Migracja bazy panelu `026_ai_access.sql` (rodzaj tokenu, pseudonimy) – stosowana automatycznie przy starcie siem-api.
- Uprawnienie *Dostęp AI (MCP)* ma tylko profil administratora; innym profilom nadaj je ręcznie.
- `vardr-mcp.exe` buduje `deploy.sh tools` (laboratorium) i paczka instalacyjna (`agent-dist/`).

## [1.3.0] – 2026-10-26 – Ryzyko osób i komputerów

### Dodane
- **Scoring ryzyka osób i komputerów** (*Wykrywanie → Ryzyko*, [docs/panel.md](docs/panel.md#ryzyko-osób-i-komputerów)): wynik to suma punktów za alerty według poziomu, wygasających w czasie (połowa co 14 dni), z mnożnikiem dla kont uprzywilejowanych i komputerów krytycznych (grupy agentów). Liczony na osobie (`user.identity` – AD, Entra ID i VPN razem) i na komputerze; poziomy niskie, średnie, wysokie i krytyczne z progami w ustawieniach. Ranking, alerty składające się na wynik, odznaka ryzyka przy osobie i komputerze w alercie i na stronie agenta. Wyniki przelicza siem-detector co 5 minut.
- **Rozstrzygnięcie przy zamknięciu alertu:** prawdziwy alarm, uzasadnione działanie albo fałszywy alarm (także w zamknięciu zbiorczym i w API: pole `resolution`); dwa ostatnie nie liczą się do ryzyka.
- **Reguła wbudowana „Ryzyko krytyczne osoby lub komputera”** (`vardr-risk-critical`): alert, gdy osoba albo komputer wchodzi w poziom krytyczny.
- **Uprawnienie „Ryzyko osób i komputerów”** (odczyt, zmiana ustawień) – ranking pracowników to profilowanie (RODO): profil *Analityk* ma odczyt, *Obserwator* – nie, profile własne – dopiero po nadaniu. Zmiana ustawień z hasłem i wpisem w audycie.

### Bezpieczeństwo
- Historia zapytań tokenów API zapamiętuje kod odpowiedzi bez opakowywania zapisu treści – treść idzie wprost do odpowiedzi HTTP z typem ustawionym przez handler (CodeQL `go/reflected-xss`; odpowiedzi API były i są JSON-em z `nosniff`, alert bez realnej podatności).

### Aktualizacja
- Migracja bazy detekcji `014_risk.sql` (rozstrzygnięcie alertu, ustawienia i wyniki ryzyka) – stosuje ją siem-detector przy starcie; zaktualizuj detektor przed panelem.
- Profile własne nie dostają uprawnienia „Ryzyko osób i komputerów” automatycznie – nadaj je w *Profilach uprawnień*, jeśli trzeba.

## [1.2.0] – 2026-10-26 – API, Microsoft Teams

### Dodane
- **Tokeny API** (*Administracja → Tokeny API*, [docs/panel.md](docs/panel.md#tokeny-api)): programy i integracje korzystają z API panelu nagłówkiem `Authorization: Bearer vardr_…`. Token ma profil uprawnień jak konto, ważność od 1 do 365 dni (domyślnie 90), zapis ostatniego użycia i natychmiastowe unieważnienie; sekret pokazywany raz, w bazie tylko skrót. Tworzenie z potwierdzeniem hasłem, zapis w audycie.
- Token nie zarządza kontami, profilami ani tokenami, nie wykonuje operacji wymagających hasła ani tras konta (sesja, MFA) – niezależnie od profilu.
- Zmiany wykonane tokenem są w audycie jako `api:<nazwa>`; odmowa dostępu dla tokenu – wpis `api_token_denied`.
- **Historia zapytań tokenów:** każde zapytanie (metoda, ścieżka z parametrami, wynik, czas odpowiedzi, adres) w panelu – licznik z 24 h i historia przy tokenie – oraz w logu siem-api. Przechowywana 30 dni (`SIEM_API_TOKEN_LOG_DAYS`).
- Limit zapytań na token (`SIEM_API_TOKEN_RATE`, domyślnie 600 na minutę, powyżej – 429).
- `GET /api/v1/api-tokens/self` – opis tokenu, którym przedstawia się program.
- **Powiadomienia w Microsoft Teams przez Power Automate** ([docs/panel.md](docs/panel.md#microsoft-teams-przez-power-automate)): nowy rodzaj kanału *Power Automate / Teams* – wiadomość jako karta Adaptive Card (tytuł w kolorze ważności, pola, przycisk „Vardr – Panel”) dla szablonu Teams „Post to a channel when a webhook request is received”, a dane strukturalne w polu `vardr` dla własnych przepływów (tickety, SMS, eskalacje). Panel przyjmuje tylko adresy wyzwalaczy Power Automate (`*.logic.azure.com`, `*.api.powerplatform.com`).
- **Podpis HMAC wiadomości** na kanałach webhook i Power Automate / Teams: nagłówki `X-Vardr-Timestamp` i `X-Vardr-Signature` (`sha256=` HMAC-SHA256 nad `<znacznik>.<treść>`); sekret pokazywany raz, nowy sekret i wyłączenie podpisu z hasłem; przykład sprawdzania w dokumentacji.
- **Opis OpenAPI 3.1** pod `GET /api/v1/openapi.json`: wszystkie trasy z wymaganym uprawnieniem i dostępnością dla tokenów, parametry zapytań alertów, zdarzeń, incydentów i audytu. Powstaje z tej samej tabeli tras co serwer.

### Zmienione
- Profilu uprawnień z ważnym tokenem API nie można usunąć (jak profilu z kontami).
- Wiadomość testowa kanału jest w języku systemu (wcześniej zawsze po polsku).

### Aktualizacja
- Migracje bazy panelu `023_api_tokens.sql`, `024_api_token_requests.sql` i `025_notify_teams.sql` – stosowane automatycznie przy starcie siem-api.

## [1.0.2] – 2026-10-23 – Poprawki bezpieczeństwa

### Bezpieczeństwo
- Czytnik eksportu (`odczytaj.exe`) przy rozpakowywaniu paczki `.tar` odrzuca także ścieżki względne do dysku (`C:plik`), ścieżki sieciowe i nazwy zarezerwowane Windows (`NUL`, `COM1`) – wcześniej odrzucał tylko ścieżki bezwzględne i `..` (CodeQL `go/zipslip`).
- Normalizator: odwołania znakowe w XML zdarzeń Windows ponad zakres Unicode są odrzucane przed konwersją typu (CodeQL `go/incorrect-integer-conversion`; wcześniej też były odrzucane, ale dopiero po konwersji).

## [1.0.1] – 2026-10-23 – English update

> 🇬🇧 **English update.** Vardr is now available in English: the whole panel, notifications, NIS2 report drafts, rule texts, service messages, the export reader, the agent's command line and the documentation ([docs/en](docs/en/README.md)). Service logs and server scripts are in English. Every account chooses its panel language; the administrator chooses the system language for notifications.

### Dodane
- **Panel po angielsku.** Cały interfejs (wszystkie moduły, okna, komunikaty) jest dostępny po polsku i po angielsku. Język wybiera się w menu konta (*Język*: jak w przeglądarce, polski, English); wybór jest zapisany na koncie i działa na każdym komputerze. Przed zalogowaniem panel bierze język przeglądarki.
- Tłumaczenia ładuje przeglądarka (osobne małe pliki dla każdego modułu i języka) – serwer nie wykonuje dodatkowej pracy. Kolejny język to zestaw plików JSON bez zmian w kodzie ([docs/rozwoj.md](docs/rozwoj.md#tłumaczenie-panelu)).
- Komunikaty błędów API, stan systemu (Himinbjörg), problemy agentów, opisy uprawnień i wyniki zapisu (tożsamości, dekodery) w języku użytkownika – serwer podaje stałe kody, tekst dobiera panel.
- Daty, godziny, liczby i dni tygodnia w formacie wybranego języka.
- Przywracanie kopii zapasowej można potwierdzić słowem `RESTORE` (obok dotychczasowego `PRZYWRÓĆ`).
- **Język systemu** (Powiadomienia → *Język systemu*, administrator panelu, zapis w audycie): język wiadomości na kanałach (alerty, rozwiązane alerty, podsumowania, incydenty, przypomnienia o terminach NIS2, kotwica archiwum), domyślny język szkiców zgłoszeń NIS2 oraz komunikatów usług zapisywanych dla panelu (wyniki kopii zapasowych, testu połączenia i przywracania, weryfikacji archiwum, obsługi niezgodności, błędy eksportów). Domyślnie polski.
- Szkic zgłoszenia NIS2 można wygenerować po polsku albo po angielsku (wybór obok przycisku szkicu).
- **Tłumaczenia reguł** (`vardr.i18n` w pliku reguły – [docs/reguly.md](docs/reguly.md#rozszerzenia-vardra)): wszystkie własne reguły Vardra i reguły wbudowane mają angielski tytuł, opis i instrukcję. Alert zapisuje teksty w obu językach; panel pokazuje je w języku konta, powiadomienia – w języku systemu. Reguły SigmaHQ są po angielsku jak w oryginale.
- Alerty zdrowia z Grafany mają angielskie podsumowanie i opis (adnotacje `summary_en`, `description_en`).
- **Walidacja w języku konta:** błędy reguł (lista błędów wczytania, test reguły, ostrzeżenia ATT&CK), dekoderów (edytor, kreator, test), ustawień kopii zapasowych, limitów grup agentów, połączenia LDAP, haseł i kanałów powiadomień panel pokazuje po angielsku kontom angielskim (API zwraca `message_en`, wyniki testów `error_en`).
- **Agent Windows i czytnik eksportu po angielsku:** `vardr-agent` (polecenia, `status`, instalator, ostrzeżenia w panelu) i `odczytaj.exe` (raport i pliki dzienne) mówią w języku Windows – po polsku albo po angielsku; wymuszenie zmienną `VARDR_LANG=pl|en`. Opisy zdarzeń Windows w raporcie czytnika w obu językach.
- Paczka eksportu dla audytora zawiera opis po angielsku (`README-EN.txt`); nagłówki `zdarzenia.csv` i notatka w `export.json` w języku systemu. Skrypt `narzedzia/odczytaj_segmenty.py` pisze w języku systemu operacyjnego (opcja `--print` obok `--wypisz`).
- **Polityka bezpieczeństwa** (`SECURITY.md`): zgłaszanie podatności prywatnie przez GitHub (*Report a vulnerability*).
- **Dokumentacja po angielsku** w `docs/en/` (instalacja, agent, panel, reguły, dekodery, architektura, operacje, programy, rozwój); `README.md` jest teraz po angielsku, polska strona projektu – `README.pl.md`. `CONTRIBUTING.md` w obu językach.

### Zmienione
- Oś czasu incydentu pokazuje zmiany pól nazwami (np. „waga: średnia → wysoka”) zamiast kodów; wpis o paczce dowodowej zapisuje numer eksportu i zakres.
- Odpowiedzi API dla stanu systemu, listy agentów, zapisu tożsamości i dekoderów mają dodatkowe pola z kodami (`id`, `value_key`, `issues`, `delivery`); dotychczasowe pola po polsku zostają.
- **Logi usług po angielsku** (wszystkie programy serwera, kolektor, konektor, agent – plik logu i Podgląd zdarzeń), także opisy metryk Prometheusa. Jeśli filtrujesz logi po treści komunikatów, popraw filtry.
- **Wiersz poleceń serwera po angielsku:** `install.sh`, `backup.sh`, `restore.sh`, `sigmahq-import.sh`, `enroll-service.sh`, `siem-api bootstrap-admin|reset-password|reset-mfa`, `siem-detector check`, `siem-archiver check-export`, `siem-pki`, skrypty PowerShell (`sysmon.ps1`, `vardr-gpo.ps1`).
- `backup.sh`: polecenia `password init|show|change` (dotychczasowe `haslo init|pokaz|zmien` nadal działają). Potwierdzenia słowami `YES` i `DELETE` (dotychczasowe `TAK` i `USUŃ` nadal działają).
- `siem-detector check` wypisuje `WARN` i `ERROR` (zamiast `UWAGA` i `BŁĄD`); `sigmahq-import.sh` rozpoznaje oba zapisy.
- Powody w kwarantannie zdarzeń i błędy ponownego przetwarzania są po angielsku.
- Nowe komputery: komentarze w wygenerowanym `agent.yaml` w języku Windows.

### Bez zmian
- Alerty sprzed aktualizacji: podsumowanie zostaje po polsku (tytuł i instrukcję panel bierze z tłumaczenia reguły). Migawki alertów w incydentach – tytuł z tłumaczenia reguły, podsumowanie po polsku.
- Dane zapisane wcześniej (powody zamknięć, notatki, wpisy audytu) zostają w języku, w którym powstały. Nazwa domyślnej grupy agentów („Domyślna”) jest pokazywana jako „Default” kontom angielskim, dopóki nie zostanie zmieniona.
- Nazwy katalogów w paczce eksportu (`zdarzenia/`, `narzedzia/`, `obsluga-niezgodnosci/`) i nazwy GPO są stałe (część formatu).
- Po polsku zostają: komentarze w kodzie, roadmapa, podsumowanie prac, opis laboratorium i testów obciążeniowych.

### Aktualizacja
- Migracje bazy panelu `021_user_language.sql` (kolumna języka konta) i `022_system_language_view.sql` (widok języka systemu dla archiwizatora i usługi kopii) – stosowane automatycznie przy starcie.
- Migracje bazy detekcji `012_i18n.sql` (kolumna `i18n` reguł i alertów) i `013_rule_errors_en.sql` (angielski opis błędów reguł) – stosuje je siem-detector przy starcie; zaktualizuj detektor razem z panelem.
- Grafana: nowe adnotacje w `grafana/provisioning/alerting/vardr.yaml` (wymaga zaktualizowania konfiguracji i restartu Grafany); szablon wiadomości panelu wybiera je według języka systemu.
- Agent Windows: nowa wersja z komunikatami w języku Windows – zaktualizuj agentów instalatorem MSI z panelu (Huginn → „Pobierz aktualizację agenta (MSI)”).

## Wcześniejsze wersje

Przed pierwszym wydaniem Vardr był rozwijany bez numerowanych aktualizacji – przebieg prac opisuje [docs/PODSUMOWANIE.md](docs/PODSUMOWANIE.md) i historia repozytorium.
