# Historia zmian

Vardr wychodzi w wydaniach (aktualizacjach). Tu jest to, co zmienia się między nimi – dla administratora, który aktualizuje serwer: nowe funkcje, zmiany zachowania i to, co trzeba zrobić przy aktualizacji. Format według [Keep a Changelog](https://keepachangelog.com/pl/1.1.0/), numery wersji według [SemVer](https://semver.org/lang/pl/). Aktualizacja serwera: [docs/instalacja.md](docs/instalacja.md) ([English](docs/en/installation.md#upgrade)).

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
