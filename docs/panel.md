# Panel Hliðskjálf

Panel działa pod `https://<serwer>:8444` (w laboratorium `https://192.168.88.98:8444`). Pierwsze konto administratora zakłada się na serwerze: `docker compose run --rm api bootstrap-admin -username admin` (hasło startowe pojawia się raz; przy pierwszym logowaniu panel wymusza jego zmianę).

## Role

| Rola | Może |
|---|---|
| `viewer` | czytać: agenci, zdarzenia, alerty, reguły, archiwum, stan systemu |
| `analyst` | jak `viewer` oraz praca z alertami (stan, przypisanie, notatki), test reguł i dekoderów |
| `admin` | wszystko: konta, grupy agentów, wdrażanie, dekodery, tożsamości, polityka archiwum, powiadomienia, włączanie i wyłączanie reguł |

Operacje wrażliwe (wyłączenie reguły, osłabienie polityki archiwum, token deinstalacji agenta, zmiana dekodera) wymagają ponownego podania hasła i powodu. Wszystkie zmiany trafiają do **dziennika audytu**. Sesja wygasa po bezczynności, a konto jest czasowo blokowane po serii nieudanych logowań.

## Moduły

Menu jest pogrupowane według rodzaju pracy: **Wykrywanie** (Alerty, Reguły detekcji), **Zdarzenia** (Wyszukiwarka, Tożsamości, Dekodery, Kwarantanna), **Agenci** (Lista agentów, Grupy agentów, Wdrażanie), **System** (Archiwum NIS2, Stan systemu) i **Administracja** (Użytkownicy, Powiadomienia, Kopie zapasowe, Dziennik audytu – tylko administrator). Etykieta mówi, co jest na stronie; nazwa modułu z roadmapy jest podpisem pod nią.

| Moduł | Adres | Co tam jest |
|---|---|---|
| **Start** | `/` | podsumowanie: otwarte alerty, agenci, archiwum NIS2, stan systemu |
| **Huginn** | `/agents` | lista agentów: stan (online, bez łączności, zatrzymany bez tokenu), wersja, grupa, bufor, kanały; strona agenta z heartbeatem, limitami, stanem ochrony, dziennikiem prób sabotażu i tokenami deinstalacji; unieważnienie agenta |
| **Grupy agentów** | `/groups` | profil zdarzeń (stacja robocza, serwer, kontroler domeny), limity zasobów, ochrona, próg alarmu po utracie łączności, powiadomienie o powrocie |
| **Mímir** | `/events` | wyszukiwarka zdarzeń z histogramem; szczegóły zdarzenia z polskim opisem i polami źródłowymi |
| **Tożsamości** | `/identities` | osoby i ich konta, podpowiedzi połączeń, aliasy, domeny organizacji, konta wspólne urządzeń, „Sprawdź konto” |
| **Gjallarhorn** | `/alerts` | alerty z filtrami (stan, poziom, reguła, komputer, konto, przypisany); strona alertu: zdarzenia (oś czasu), instrukcja dla analityka, powiązane alerty (komputer, konto, osoba ±24 h), notatki, przypisanie, zamknięcie z powodem |
| **Reguły detekcji** | `/rules` | lista reguł z plików i wbudowanych, treść, historia wersji, błędy wczytania, włączanie i wyłączanie, test reguły (także korelacyjnej) na zdarzeniach z ClickHouse, kreator korelacji z przykładowych zdarzeń (`/rules/correlation`) i reguły zapisane w panelu |
| **Dekodery** | `/decoders` | dekodery syslog i API w kolejności sprawdzania, edycja z historią, test na próbkach albo na nierozpoznanych wiadomościach, kreator z próbek (zaznaczanie pól w wiadomości) |
| **Kwarantanna** | `/quarantine` | zdarzenia nieznormalizowane pogrupowane według źródła i powodu, oryginały, kreator dekodera z wiadomości grupy, ponowne przetworzenie po poprawie dekodera |
| **Bifröst** | `/deploy` | tokeny rejestracyjne i paczki instalacyjne agenta (ZIP z programem, CA i tokenem) |
| **Urd** | `/archive` | archiwum NIS2: stan, segmenty, weryfikacje, polityka (włączenie, retencja, grupy), eksporty dla audytora, odtworzenie do `siem.events_replay` |
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
