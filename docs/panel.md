# Panel Hliðskjálf

Panel działa pod `https://<serwer>:8444` (w laboratorium `https://192.168.88.98:8444`). Pierwsze konto administratora zakłada się na serwerze: `docker compose run --rm api bootstrap-admin -username admin` (hasło startowe pojawia się raz; przy pierwszym logowaniu panel wymusza jego zmianę).

## Profile uprawnień

Każde konto ma jeden **profil uprawnień** – macierz: moduł panelu → poziom dostępu. Poziomy w module są uporządkowane, wyższy obejmuje niższe (np. reguły: odczyt < test < zmiana; archiwum: odczyt < eksport < zmiana).

| Moduł | Poziomy |
|---|---|
| Alerty | odczyt, obsługa (status, przypisanie, notatki) |
| Zdarzenia (Mímir) | odczyt |
| Reguły detekcji i MITRE | odczyt, test (test na historii, kreator korelacji), zmiana (włączanie, próby, reguły z panelu) |
| Agenci i grupy | odczyt, zmiana (grupy, usuwanie, tokeny deinstalacji) |
| Wdrażanie agentów | odczyt, zmiana (tokeny rejestracji, instalatory MSI) |
| Archiwum NIS2 (Urd) | odczyt, eksport (paczki dla audytora), zmiana (polityka, weryfikacja, odtworzenie) |
| Dekodery syslog | odczyt, test, zmiana |
| Kwarantanna | odczyt, ponowne przetwarzanie |
| Tożsamości | odczyt, zmiana |
| Stan systemu | odczyt |
| Powiadomienia | odczyt, zmiana |
| Kopie zapasowe | odczyt, zmiana |
| Użytkownicy i bezpieczeństwo | odczyt, zmiana (konta, profile, wymóg MFA) |
| Dziennik audytu | odczyt |

**Profile wbudowane** odpowiadają dawnym rolom i nie da się ich zmienić ani usunąć (można je skopiować jako punkt wyjścia):

| Profil | Może |
|---|---|
| Obserwator (`viewer`) | czytać: agenci, zdarzenia, alerty, reguły, archiwum, dekodery, kwarantanna, tożsamości, stan systemu |
| Analityk (`analyst`) | jak obserwator oraz obsługa alertów, test reguł i dekoderów |
| Administrator (`admin`) | wszystko – także moduły dodane w przyszłych wersjach |

**Profile własne** tworzy się w *Administracja → Profile uprawnień* (np. „Audytor NIS2”: archiwum – eksport; „Helpdesk”: agenci – odczyt). Profil z prawem zmiany w module „Użytkownicy i bezpieczeństwo” to **administrator panelu** (wymóg MFA „administratorzy” dotyczy właśnie jego). Zapis i usunięcie profilu wymagają hasła i trafiają do audytu; panel nie pozwoli na zmianę, po której żadne aktywne konto nie byłoby administratorem, ani na usunięcie profilu z przypisanymi kontami. Zmiana profilu działa od razu (najpóźniej po 30 s) – także dla zalogowanych.

Operacje wrażliwe (wyłączenie reguły, osłabienie polityki archiwum, token deinstalacji agenta, zmiana dekodera) wymagają ponownego podania hasła i powodu. Wszystkie zmiany trafiają do **dziennika audytu**. Sesja wygasa po bezczynności, a konto jest czasowo blokowane po serii nieudanych logowań.

## Drugi składnik logowania (MFA)

Po haśle panel prosi o 6-cyfrowy kod z aplikacji uwierzytelniającej (TOTP – Microsoft/Google Authenticator, Aegis, 1Password).

- **Kogo obowiązuje** ustawia administrator w *Administracja → Użytkownicy*: wszystkich (domyślnie), tylko administratorów albo nikogo (dobrowolnie). Zmiana wymaga hasła i trafia do audytu. Po włączeniu wymogu sesje bez drugiego składnika są kończone, a konta bez aplikacji konfigurują ją przy najbliższym logowaniu (kod QR, potem kod z aplikacji). Wymogu nie włączy administrator, który sam nie ma drugiego składnika w bieżącej sesji – panel nie wyloguje go w połowie zmiany.
- **Kody zapasowe**: przy włączeniu użytkownik dostaje 10 jednorazowych kodów (pokazywanych raz) na wypadek zgubionego telefonu. Nowe kody i dobrowolne wyłączenie – *Moje konto → Bezpieczeństwo konta* (hasło i kod).
- **Zgubiony telefon bez kodów**: administrator wybiera przy koncie *Resetuj drugi składnik* (hasło, audyt) – konto skonfiguruje aplikację od nowa. Gdy dotyczy to jedynego administratora – na serwerze: `docker compose run --rm api reset-mfa -username <login>` (wpis w audycie).
- **Ochrona**: kod działa raz (ten sam kod nie zaloguje drugi raz), tolerancja zegara ±30 s, 5 złych kodów kończy próbę logowania, a nieudane kody liczą się do blokady konta. Sekrety TOTP są w bazie zaszyfrowane (AES-256-GCM) kluczem z pliku `certs/mfa.key` na serwerze – `deploy.sh config` tworzy go raz; plik jest w kopii zapasowej (`certs/`). Utrata klucza unieważnia zapisane aplikacje – konta trzeba zresetować (w panelu albo `reset-mfa`) i skonfigurować od nowa.

## Moduły

Menu jest pogrupowane według rodzaju pracy: **Wykrywanie** (Alerty, Reguły detekcji), **Zdarzenia** (Wyszukiwarka, Tożsamości, Dekodery, Kwarantanna), **Agenci** (Lista agentów, Grupy agentów, Wdrażanie), **System** (Archiwum NIS2, Stan systemu) i **Administracja** (Użytkownicy, Powiadomienia, Kopie zapasowe, Dziennik audytu – tylko administrator). Etykieta mówi, co jest na stronie; nazwa modułu z roadmapy jest podpisem pod nią.

| Moduł | Adres | Co tam jest |
|---|---|---|
| **Start** | `/` | podsumowanie: otwarte alerty, agenci, archiwum NIS2, stan systemu |
| **Huginn** | `/agents` | lista agentów: stan (online, bez łączności, zatrzymany bez tokenu, wycofany – certyfikat unieważniony po deinstalacji tokenem, osobny filtr), wersja, grupa, bufor, kanały; strona agenta z heartbeatem, limitami, stanem ochrony, dziennikiem prób sabotażu i tokenami deinstalacji; unieważnienie agenta; „Pobierz aktualizację agenta (MSI)” – instalator najnowszej wersji bez tokenu |
| **Grupy agentów** | `/groups` | profil zdarzeń (stacja robocza, serwer, kontroler domeny), limity zasobów, ochrona, próg alarmu po utracie łączności, powiadomienie o powrocie |
| **Mímir** | `/events` | wyszukiwarka zdarzeń z histogramem; szczegóły zdarzenia z polskim opisem i polami źródłowymi |
| **Tożsamości** | `/identities` | osoby i ich konta, podpowiedzi połączeń, aliasy, domeny organizacji, konta wspólne urządzeń, „Sprawdź konto” |
| **Gjallarhorn** | `/alerts` | alerty z filtrami (stan, poziom, reguła, komputer, konto, przypisany); strona alertu: zdarzenia (oś czasu), instrukcja dla analityka, powiązane alerty (komputer, konto, osoba ±24 h), notatki, przypisanie, zamknięcie z powodem |
| **MITRE ATT&CK** | `/attack` | macierz pokrycia technik regułami (kolory: alerty w okresie, pokryta, tylko wyłączone reguły, brak), filtry platformy i okresu, szczegóły techniki z regułami, podtechnikami i alertami, eksport warstwy dla ATT&CK Navigator |
| **Reguły detekcji** | `/rules` | lista reguł z plików i wbudowanych, treść, historia wersji, błędy wczytania, włączanie i wyłączanie, test reguły (także korelacyjnej) na zdarzeniach z ClickHouse, kreator korelacji z przykładowych zdarzeń (`/rules/correlation`) i reguły zapisane w panelu |
| **Dekodery** | `/decoders` | dekodery syslog i API w kolejności sprawdzania, edycja z historią, test na próbkach albo na nierozpoznanych wiadomościach, kreator z próbek (zaznaczanie pól w wiadomości) |
| **Kwarantanna** | `/quarantine` | zdarzenia nieznormalizowane pogrupowane według źródła i powodu, oryginały, kreator dekodera z wiadomości grupy, ponowne przetworzenie po poprawie dekodera |
| **Bifröst** | `/deploy` | tokeny rejestracyjne; instalator MSI z wpisanym adresem serwera i tokenem (jeden plik – instalacja albo aktualizacja podwójnym kliknięciem, wdrożenie GPO/Intune bez parametrów) i paczka ZIP |
| **Urd** | `/archive` | archiwum NIS2: stan, segmenty, weryfikacje, obsługa niezgodności (pliki nieznane spisowi – przyjęcie po sprawdzeniu sum albo kwarantanna, z przyczyną i hasłem; historia operacji), polityka (włączenie, retencja, grupy), eksporty dla audytora, odtworzenie do `siem.events_replay` |
| **Himinbjörg** | `/system` | stan usług, kolejek, dysków i baz (z Prometheusa); linki do Grafany: pulpity „zdrowie potoku” i „przegląd zdarzeń”, aktywne alerty, reguły alertów, Explore – z wybranym zakresem czasu, a przy każdej grupie i problemie wykresy tej dziedziny |
| **Użytkownicy** | `/admin/users` | konta, role, reset hasła |
| **Dziennik audytu** | `/admin/audit` | kto, co i kiedy zmienił w panelu |
| **Kopie zapasowe** | `/admin/backup` | zakładki: *Ustawienia* (harmonogram, zawartość, retencja, miejsce docelowe SFTP/SMB/S3 z poświadczeniami), *Historia* kopii, *Przywracanie* (lista kopii, sprawdzenie zawartości, przywrócenie bazy z konfiguracją i/lub Grafany z kopią obecnego stanu); kopia na żądanie, test połączenia |
| **Powiadomienia** | `/admin/notifications` | kanały (Discord, webhook) z rodzajami wiadomości (alerty z filtrem poziomu i reguł, zdrowie, kotwica archiwum), test kanału |

## Wyszukiwanie zdarzeń (Mímir)

Zapytanie to lista warunków oddzielonych spacjami, łączonych przez I:

| Składnia | Znaczenie | Przykład |
|---|---|---|
| `pole:wartość` | pole równe wartości (tekst bez wielkości liter) | `user:jkowalski code:4625` |
| `pole:prefiks*` | pole zaczyna się od | `host:pc0*` |
| `-pole:wartość` | negacja | `-action:logged-out` |
| `słowo`, `"fraza"` | tekst w treści zdarzenia (opis i surowy XML) | `"invoke-expression" powershell` |
| `fields.Nazwa:wartość` | pole źródłowe zdarzenia (mapa `fields`) | `fields.TargetUserName:admin` |

Pola: `host` (`computer`), `agent`, `user`, `domain`, `identity` (`osoba`, `person`), `ip` (`src`), `code` (`id`, `eventid`), `action`, `outcome`, `dataset` (`channel`), `provider`, `process`. Lista z opisami jest w panelu (pomoc przy polu zapytania, `GET /api/v1/events/fields`).

Zakres czasu wybiera się nad wynikami. Wyszukiwanie korzysta z konta ClickHouse tylko do odczytu z limitem czasu (30 s) i wyniku, więc zbyt szerokie zapytanie kończy się komunikatem, a nie obciążeniem serwera; zawęź wtedy czas albo dodaj pole.

## Praca z alertem

1. **Przyjęcie.** Alert przychodzi na kanał powiadomień (Discord) z poziomem, opisem i linkiem.
2. **W analizie.** Analityk otwiera alert i przypisuje go sobie; stan zmienia się na „w analizie” (`acknowledged`).
3. **Analiza.** Instrukcja w alercie mówi, co sprawdzić. Oś zdarzeń pokazuje zdarzenia alertu, a z każdego można przejść do Mímira. Powiązane alerty pokazują, co jeszcze działo się na tym komputerze, koncie i u tej osoby.
4. **Notatki.** Ustalenia trafiają do notatek (oś czasu alertu).
5. **Zamknięcie.** Alert zamyka się z powodem, np. „fałszywy alarm – skaner podatności” albo „incydent – zmienione hasło”. Wiele alertów naraz zamyka akcja zbiorcza.

Alerty utraty łączności i ciszy źródła zamykają się same, gdy agent albo źródło wróci. Zamknięte alerty są usuwane po `SIEM_ALERT_RETENTION_DAYS` (domyślnie 365 dni).

Kolejne trafienia tej samej reguły z tym samym kluczem (np. ta sama osoba, ten sam adres) w oknie łączenia trafiają do tego samego alertu: rośnie licznik, a zdarzenia dochodzą do osi. Gdy jedna reguła wywołuje ponad `SIEM_ALERT_NOTIFY_PER_RULE` nowych alertów w `SIEM_ALERT_NOTIFY_WINDOW`, kanał dostaje jedną wiadomość zbiorczą zamiast serii.

## API

Panel jest klientem własnego API JSON (`/api/v1/…`, sesja w ciasteczku `HttpOnly`, ochrona CSRF nagłówkiem `X-CSRF-Token`). Lista tras: `panel/internal/api/server.go` (`Handler`). Agenci korzystają z osobnych tras bez sesji, uwierzytelnianych tokenem albo certyfikatem: `/enroll/v1/register`, `/enroll/v1/renew`, `/enroll/v1/config`.
