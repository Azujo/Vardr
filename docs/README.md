# Dokumentacja Vardra

Vardr to własny system SIEM: agenci i kolektory zbierają zdarzenia (Windows, syslog, Entra ID), serwer je normalizuje, zapisuje, wykrywa zagrożenia i archiwizuje zgodnie z NIS2, a panel Hliðskjálf służy do analizy i zarządzania.

Ta dokumentacja opisuje system tak, jak działa po etapie 8 (MVP, październik 2026). Plany i decyzje projektowe są w [ROADMAP.md](ROADMAP.md), przebieg prac i znane luki w [PODSUMOWANIE.md](PODSUMOWANIE.md), a instrukcje instalacji krok po kroku w [README.md](../README.md) w katalogu głównym.

## Spis

| Dokument | Dla kogo | Co zawiera |
|---|---|---|
| [Architektura](architektura.md) | każdy | składniki, przepływ zdarzenia, kolejki NATS, tabele ClickHouse i PostgreSQL, detekcja, archiwum, bezpieczeństwo, struktura repozytorium |
| [Programy](programy.md) | administrator, programista | każdy program: do czego służy, polecenia, flagi, zmienne środowiskowe, porty, metryki |
| [Panel](panel.md) | analityk, administrator | moduły panelu, role, język wyszukiwania zdarzeń, triage alertów |
| [Reguły detekcji](reguly.md) | autor reguł | format Sigma z rozszerzeniami Vardra, pola, progi, tryby silników, reguły wbudowane, testowanie i wdrażanie |
| [Dekodery](dekodery.md) | autor dekoderów | dekodery syslog i API: dopasowanie, parsery, mapowanie pól, wynik, czas, próbki |
| [Operacje](operacje.md) | administrator | laboratorium: wdrażanie, kopie, retencja, migracje, skrypty, diagnostyka |
| [Testy obciążeniowe](testy-obciazeniowe.md) | programista, administrator | generator ruchu, monitor, sprzątanie, wyniki i pojemność |
| [Rozwój](rozwoj.md) | programista | budowanie, testy, CI, konwencje kodu, jak dodać źródło, regułę wbudowaną czy migrację |

## Nazwy

Moduły mają nazwy z mitologii nordyckiej (pełna lista: [ROADMAP.md, załącznik D](ROADMAP.md#załącznik-d-nazewnictwo--vardr-i-jego-świat)):

| Nazwa | Co to jest |
|---|---|
| **Vardr** | cały system |
| **Hliðskjálf** | panel WWW (`siem-api` z wbudowanym frontendem) |
| **Huginn** | lista agentów i ich stan (moduł panelu) |
| **Bifröst** | wdrażanie agentów: paczki i tokeny rejestracyjne |
| **Mímir** | wyszukiwarka zdarzeń |
| **Gjallarhorn** | detekcja i alerty (`siem-detector`, schemat `gjallarhorn`) |
| **Urd** | archiwum NIS2 (`siem-archiver`, schemat `urd`) |
| **Himinbjörg** | strona stanu systemu |
| **Saga** | baza PostgreSQL panelu, alertów i archiwum |

## Słowniczek

- **Agent** – program na komputerze (Windows) albo serwerze (kolektor syslog, konektor API), który zbiera zdarzenia i wysyła je paczkami przez mTLS.
- **Paczka** – porcja zdarzeń od jednego agenta (kontrakt: [ROADMAP.md, załącznik A](ROADMAP.md#załącznik-a-kontrakt-paczki-agent--serwer-v1)).
- **Zdarzenie znormalizowane** – wspólny model (`internal/model.Event`): czas, komputer, konto, osoba, adres, akcja, wynik, pola źródłowe.
- **Osoba (`user.identity`)** – ten sam człowiek za kontami w AD, Entra ID i na VPN.
- **Zbiór (`event.dataset`)** – źródło zdarzenia, np. `windows.security`, `fortinet.fortigate`, `azure.signinlogs`.
- **Silnik w locie** – detekcja na strumieniu NATS, zdarzenie po zdarzeniu.
- **Silnik zapytań** – ta sama reguła jako zapytanie SQL do ClickHouse, co minutę, nadrabia to, czego silnik w locie nie widział.
- **Korelacja** – reguła wbudowana łącząca zdarzenia z wielu źródeł po osobie.
- **Kwarantanna** – zdarzenia, których nie udało się znormalizować (oryginał i powód).
