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

Porty: `8443/tcp` (agenci), `8444/tcp` (panel), `3000/tcp` (Grafana), opcjonalnie `514/udp+tcp` i `6514/tcp` (kolektor syslog, TLS) – kto ma do nich dostęp: [Zapora](#zapora).

## Instalacja

Paczkę i plik `SHA256SUMS` pobierz z [najnowszego wydania](https://github.com/Azujo/Vardr/releases/latest) (albo zbuduj samodzielnie – niżej) i sprawdź sumę: `sha256sum -c --ignore-missing SHA256SUMS`.

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

## Zapora

Do serwera powinny mieć dostęp tylko te sieci, które go potrzebują:

| Port | Kto |
|---|---|
| `8443/tcp` (ingest) | sieci z komputerami z agentem |
| `8444/tcp` (panel) | sieć administratorów i SOC |
| `3000/tcp` (Grafana) | administratorzy – albo wcale (niżej) |
| `514/udp+tcp`, `6514/tcp` (kolektor, 6514 – TLS) | sieci urządzeń wysyłających syslog (dodatkowo lista `syslog.allow` kolektora) |
| `22/tcp` (SSH) | administratorzy |

**Docker omija ufw i firewalld** – porty kontenerów są publikowane regułami Dockera, przed regułami INPUT. Ruch do kontenerów filtruje się w łańcuchu `DOCKER-USER`, po porcie sprzed przekierowania (`--ctorigdstport`), np. panel i Grafana tylko z `10.0.10.0/24`:

```bash
sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8444 --ctdir ORIGINAL ! -s 10.0.10.0/24 -j DROP
sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 3000 --ctdir ORIGINAL ! -s 10.0.10.0/24 -j DROP
sudo apt install iptables-persistent && sudo netfilter-persistent save   # zachowanie po restarcie
```

SSH i inne usługi samego serwera – zwykle (ufw, firewalld).

**Grafana bez dostępu z sieci:** `VARDR_GRAFANA_ADDR=127.0.0.1` w `/opt/vardr/.env`, potem `sudo systemctl restart vardr`. Grafana jest wtedy dostępna tylko tunelem SSH (`ssh -L 3000:127.0.0.1:3000 admin@serwer`, w przeglądarce `http://localhost:3000`); odnośniki do Grafany w panelu działają przy otwartym tunelu.

## Kopia archiwum w S3

Archiwum NIS2 leży na dysku serwera – administrator serwera (albo napastnik, który go przejmie) może je usunąć. Kopia w magazynie S3 z **blokadą obiektów (Object Lock) w trybie COMPLIANCE** jest nie do usunięcia ani nadpisania do końca retencji – także przez właściciela konta magazynu. Archiwizator wysyła do niej każdą zamkniętą godzinę (segmenty, na końcu manifest) w ciągu kilku minut; blokada obiektu trwa do końca godziny + bieżącej retencji z panelu. Działa z AWS S3 i zgodnymi magazynami: Wasabi, Backblaze B2, MinIO, Ceph RGW.

1. Załóż kubełek **z włączonym Object Lock** (da się to zrobić tylko przy zakładaniu; włącza też wersjonowanie). Reguła domyślna nie jest potrzebna – Vardr ustawia blokadę każdego obiektu.
2. Załóż użytkownika (klucz dostępu) z uprawnieniami tylko do tego kubełka: `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetBucketObjectLockConfiguration` (bez usuwania).
3. Dopisz do `/opt/vardr/.env` i uruchom ponownie (`sudo systemctl restart vardr`):

```bash
SIEM_ARCHIVE_S3_BUCKET=vardr-archiwum
SIEM_ARCHIVE_S3_ENDPOINT=https://s3.eu-central-1.amazonaws.com   # MinIO: https://minio.firma.local:9000
SIEM_ARCHIVE_S3_REGION=eu-central-1
SIEM_ARCHIVE_S3_ACCESS_KEY=…
SIEM_ARCHIVE_S3_SECRET_KEY=…
#SIEM_ARCHIVE_S3_PREFIX=serwer1        # kilka instalacji w jednym kubełku
#SIEM_ARCHIVE_S3_MODE=GOVERNANCE       # blokada, którą uprawniony użytkownik może zdjąć (testy)
```

Godziny sprzed włączenia kopii są wysyłane od najstarszej w retencji. Kubełek bez Object Lock archiwizator odrzuca (nic nie wysyła). Stan: *Stan systemu → Kopia w S3 (Object Lock)*, metryki `siem_archive_offsite_*`, logi archiwizatora (`archive copy`).

Wygasłe obiekty usuwa reguła cyklu życia kubełka (np. usuwanie wersji nieaktualnych i obiektów starszych niż retencja + 2 dni) – zablokowanych magazyn i tak nie usunie przed czasem. Kopia ma ten sam układ katalogów co archiwum: po utracie serwera pobierz ją do katalogu archiwum nowej instalacji (np. `aws s3 sync`), przywróć bazę z kopii zapasowej (`restore.sh`) i uzgodnij archiwum w panelu (Urd → obsługa niezgodności).

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
