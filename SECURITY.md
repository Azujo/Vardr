# Security policy

🇬🇧 English · 🇵🇱 [Polski](#polityka-bezpieczeństwa)

## Supported versions

Security fixes are released for the latest version only. Upgrade to the newest release before reporting ([CHANGELOG](CHANGELOG.md), [upgrade](docs/en/installation.md#upgrade)).

| Version | Supported |
|---|---|
| 1.0.x (latest) | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Do not report vulnerabilities in a public issue, pull request or discussion.**

Report privately through GitHub: [**Report a vulnerability**](https://github.com/Azujo/Vardr/security/advisories/new) (the *Security* tab of the repository → *Report a vulnerability*). Only the maintainer sees the report.

Please include:

- the affected component (agent, collector, connector, a server service, the panel) and version,
- a description of the problem and its impact,
- steps to reproduce or a proof of concept,
- your suggested fix, if you have one.

Do not include real data from your systems (events, logs, keys, passwords) – anonymize them.

## What to expect

- Confirmation of the report within **7 days**.
- An assessment and a fix plan within **30 days**; critical issues are handled first.
- A fixed release with a note in the CHANGELOG and a GitHub security advisory. You will be credited unless you prefer otherwise.

Vardr is developed by one person in their spare time, so please be patient – and thank you for reporting responsibly.

## Scope

In scope: the code in this repository – the Windows agent, collector and connector, server services, the Hliðskjálf panel, installation and backup scripts.

Out of scope: vulnerabilities in third-party software (PostgreSQL, ClickHouse, NATS, Grafana, the operating system) – report them to their vendors; misconfiguration of a particular installation; the lab configuration in `deploy/lab` used only for development.

---

# Polityka bezpieczeństwa

## Wspierane wersje

Poprawki bezpieczeństwa wychodzą tylko dla najnowszej wersji. Przed zgłoszeniem zaktualizuj Vardra do najnowszego wydania ([CHANGELOG](CHANGELOG.md), [aktualizacja](docs/instalacja.md#aktualizacja)).

| Wersja | Wspierana |
|---|---|
| 1.0.x (najnowsza) | ✅ |
| starsze | ❌ |

## Zgłaszanie podatności

**Nie zgłaszaj podatności w publicznym zgłoszeniu (issue), pull requeście ani dyskusji.**

Zgłoś ją prywatnie przez GitHub: [**Report a vulnerability**](https://github.com/Azujo/Vardr/security/advisories/new) (zakładka *Security* repozytorium → *Report a vulnerability*). Zgłoszenie widzi tylko opiekun projektu.

Opisz:

- którego elementu dotyczy (agent, kolektor, konektor, usługa serwera, panel) i wersję,
- na czym polega problem i jakie ma skutki,
- jak go odtworzyć (kroki albo proof of concept),
- propozycję poprawki, jeśli ją masz.

Nie dołączaj prawdziwych danych ze swoich systemów (zdarzeń, logów, kluczy, haseł) – zanonimizuj je.

## Czego się spodziewać

- Potwierdzenie zgłoszenia w ciągu **7 dni**.
- Ocena i plan poprawki w ciągu **30 dni**; problemy krytyczne – w pierwszej kolejności.
- Wydanie z poprawką, opis w CHANGELOG i komunikat bezpieczeństwa na GitHubie. Zgłaszający jest wymieniony z nazwy, chyba że woli inaczej.

Vardra rozwija jedna osoba po godzinach – prosimy o cierpliwość i dziękujemy za odpowiedzialne zgłoszenie.

## Zakres

W zakresie: kod z tego repozytorium – agent Windows, kolektor i konektor, usługi serwera, panel Hliðskjálf, skrypty instalacji i kopii zapasowych.

Poza zakresem: podatności w oprogramowaniu innych producentów (PostgreSQL, ClickHouse, NATS, Grafana, system operacyjny) – zgłaszaj je producentom; błędna konfiguracja konkretnej instalacji; konfiguracja laboratorium w `deploy/lab`, używana tylko do rozwoju.
