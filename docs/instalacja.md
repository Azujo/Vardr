# Instalacja serwera Vardr

Serwer Vardr instaluje się z paczki `vardr-<wersja>-linux-amd64.tar.gz`: programy, pliki stosu Docker Compose, reguły detekcji, agent Windows i skrypt `install.sh`. Obrazy usług powstają lokalnie z programów w paczce; z sieci pobierane są tylko obrazy bazowe (NATS, ClickHouse, PostgreSQL, Grafana, Prometheus).

## Wymagania

| | Minimum | Zalecane |
|---|---|---|
| System | Linux x86_64 z systemd (Debian 12/13, Ubuntu 24.04) | |
| Docker | Docker Engine z wtyczką compose 2.20+ ([instrukcja](https://docs.docker.com/engine/install/)) | |
| Pamięć | 4 GB | 8 GB i więcej |
| Dysk (katalog Dockera) | 20 GB | 60 GB i więcej (kolejki, baza zdarzeń) |
| Archiwum NIS2 | | osobny dysk pod `/srv/vardr` |

Porty: `8443/tcp` (agenci), `8444/tcp` (panel), `3000/tcp` (Grafana), opcjonalnie `514/udp+tcp` (kolektor syslog).

## Instalacja

```bash
tar xzf vardr-<wersja>-linux-amd64.tar.gz
cd vardr-<wersja>-linux-amd64
sudo ./install.sh
```

Instalator pyta o adresy serwera (nazwy DNS i IP, pod którymi łączą się agenci i przeglądarki; pierwszy trafia do paczek agentów) i katalog danych. Bez pytań: `sudo ./install.sh --server siem.firma.pl,10.0.0.5 --yes`. Opcje: `--dir` (pliki stosu, domyślnie `/opt/vardr`), `--data` (archiwum, eksporty, kopie, domyślnie `/srv/vardr`), `--admin` (pierwsze konto panelu, domyślnie `admin`).

Co robi:

1. sprawdza system (Docker, pamięć, miejsce, wolne porty) i doinstalowuje brakujące narzędzia (openssl, gpg, curl);
2. zakłada użytkownika systemowego `vardr` – właściciela plików, pod którym działają usługi;
3. kopiuje stos do `/opt/vardr`, tworzy `.env` z losowymi hasłami (tylko root i `vardr`);
4. tworzy urząd certyfikacji Vardra, certyfikat serwera z podanymi adresami, CA rejestracji agentów i klucz szyfrujący sekrety MFA;
5. buduje obrazy usług i instalator MSI agenta z certyfikatem tego serwera;
6. rejestruje usługi systemd: `vardr` (stos startuje z systemem) i `vardr-restore.timer` (przywracanie z kopii zlecone w panelu);
7. uruchamia stos, czeka na panel, zakłada pierwsze konto administratora i pokazuje hasło startowe;
8. na końcu pokazuje **hasło kopii zapasowych** – zapisz je poza serwerem, bez niego kopii nie da się odszyfrować.

Komunikaty instalatora i skryptów serwera są po angielsku. Język panelu wybiera każde konto (menu konta), a język powiadomień i szkiców zgłoszeń NIS2 – administrator w panelu (*Powiadomienia → Język systemu*).

Panel ma certyfikat lokalnego urzędu Vardra: zaimportuj `/opt/vardr/certs/ca.crt` do zaufanych urzędów w przeglądarce (instalator pokazuje odcisk SHA-256 do porównania). Agentów instaluje się z paczek pobieranych w panelu (*Agenci*).

## Aktualizacja

To samo polecenie z nowszej paczki: `sudo ./install.sh`. Instalator podmienia programy, pliki stosu i reguły (nowa wersja w `rules/v<czas>`, zostają 3 ostatnie), dopisuje do `.env` nowe ustawienia i odtwarza tylko zmienione usługi. Konfiguracja, certyfikaty i dane zostają. Certyfikat serwera (ważny rok) jest odnawiany, gdy do wygaśnięcia zostało mniej niż 45 dni.

## Reguły SigmaHQ

Paczka zawiera tylko reguły Vardra. Otwartą bibliotekę reguł [SigmaHQ](https://github.com/SigmaHQ/sigma) (licencja DRL 1.1) importuje się na serwerze jednym poleceniem – reguły trafiają **wyłączone**, a włącza się je w panelu (najlepiej przez tryb próbny):

```bash
sudo /opt/vardr/sigmahq-import.sh
```

Szczegóły: [reguly.md](reguly.md#import-reguł-sigmahq) i panel: *Reguły → Import reguł SigmaHQ*.

## Kolektor syslog i konektor API

Opcjonalne usługi stosu (profile Docker Compose), rejestrowane jednorazowym tokenem bez przeklejania:

```bash
sudo /opt/vardr/enroll-service.sh collector [grupa agentów]
sudo /opt/vardr/enroll-service.sh connector [grupa agentów]
```

Usługa trafia do `COMPOSE_PROFILES` w `.env` i startuje razem ze stosem. Konektor wymaga potem danych aplikacji Entra ID: `tenant_id` i `client_id` w `connector/connector.yaml`, sekret w `connector/entra.secret`.

## Obsługa

```bash
cd /opt/vardr
sudo docker compose ps              # stan usług
sudo docker compose logs -f api     # log usługi
sudo systemctl restart vardr        # restart stosu
sudo ./backup.sh                    # kopia zapasowa teraz
sudo ./backup.sh password show      # hasło kopii (dawniej: haslo pokaz)
```

Kopie zapasowe, przywracanie, archiwum i odtworzenie na nowym serwerze: [operacje.md](operacje.md).

## Usunięcie

```bash
sudo ./install.sh --uninstall           # usługi; dane i konfiguracja zostają
sudo ./install.sh --uninstall --purge   # także bazy, archiwum i kopie (potwierdzenie słowem DELETE albo USUŃ)
```

## Budowanie paczki

Na stacji z Go (Git Bash na Windows albo Linux):

```bash
deploy/vardr/build-bundle.sh [wersja]
```

Wynik: `dist/vardr-<wersja>-linux-amd64.tar.gz` i plik `.sha256`. Frontend panelu buduje się przez npm, a bez Node używany jest gotowy `panel/web/dist` (np. z `deploy/lab/deploy.sh web`). Plik stosu instalacji to `deploy/vardr/docker-compose.yml`; konfiguracja usług i skrypty kopii są wspólne ze stosem laboratorium (`deploy/lab`).
