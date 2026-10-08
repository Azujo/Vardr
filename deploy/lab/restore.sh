#!/bin/bash
# Odtworzenie Heimdalla z kopii zapasowej na czystej VM (Docker zainstalowany,
# stos skopiowany: deploy/lab/deploy.sh config + usługi).
#
#   ./restore.sh <heimdall-….tar.gpg> [katalog z paczkami urd-….tar.gpg]
#
# Kroki:
#   1. odszyfrowanie kopii (gpg zapyta o hasło kopii; albo plik z hasłem
#      w HEIMDALL_BACKUP_PASS_FILE),
#   2. certs/ i .env do katalogu stosu (istniejące pliki zostają z rozszerzeniem
#      .przed-odtworzeniem),
#   3. baza Saga: start kontenera, pg_restore (konta, agenci, certyfikaty,
#      grupy, spis archiwum NIS2, polityka, kanały powiadomień),
#   4. opcjonalnie archiwum NIS2: paczki urd-… po kolei do SIEM_ARCHIVE_PATH,
#   5. start całego stosu.
#
# Czego kopia nie zawiera: zdarzeń w ClickHouse (kilka dni, odtwarzalne
# z archiwum – panel → Urd → Odtworzenie) i kolejek NATS (agenci dosyłają
# zaległe zdarzenia sami).
set -euo pipefail
cd "$(dirname "$0")"
umask 077

backup="${1:-}"
urd_dir="${2:-}"
if [ -z "$backup" ] || [ ! -f "$backup" ]; then
  echo "użycie: ./restore.sh <heimdall-….tar.gpg> [katalog z paczkami urd-….tar.gpg]" >&2
  exit 2
fi
[ -f docker-compose.yml ] || { echo "uruchom w katalogu stosu (docker-compose.yml)" >&2; exit 2; }

pass_args=()
if [ -n "${HEIMDALL_BACKUP_PASS_FILE:-}" ]; then
  pass_args=(--batch --pinentry-mode loopback --passphrase-file "$HEIMDALL_BACKUP_PASS_FILE")
fi
decrypt() { gpg --quiet "${pass_args[@]}" --decrypt "$1"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== 1. odszyfrowanie $backup"
decrypt "$backup" | tar -C "$work" -xf -
cat "$work/KOPIA.txt"
docker run --rm -i postgres:18-alpine pg_restore --list < "$work/saga.dump" > /dev/null || {
  echo "kopia bazy nieczytelna" >&2
  exit 1
}

echo
echo "Odtworzenie ZASTĄPI bazę Saga na tym serwerze danymi z kopii."
read -r -p "Kontynuować? Wpisz TAK: " ok
[ "$ok" = TAK ] || { echo "Przerwano."; exit 1; }

echo "== 2. certs/ i .env"
for f in .env certs; do
  if [ -e "$f" ]; then
    rm -rf "$f.przed-odtworzeniem"
    mv "$f" "$f.przed-odtworzeniem"
  fi
  cp -r "$work/$f" "$f"
done
chmod 600 .env

echo "== 3. baza Saga"
docker compose up -d saga
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q saga)")" = healthy ] && break
  sleep 2
done
docker compose exec -T saga pg_restore -U saga_admin -d saga --clean --if-exists < "$work/saga.dump"

if [ -n "$urd_dir" ]; then
  echo "== 4. archiwum NIS2"
  set -a
  . ./.env
  set +a
  arch="${SIEM_ARCHIVE_PATH:-./archive}"
  mkdir -p "$arch"
  n=0
  for b in $(find "$urd_dir" -maxdepth 1 -name 'urd-*.tar.gpg' | LC_ALL=C sort); do
    decrypt "$b" | tar -C "$arch" -xf -
    n=$((n + 1))
  done
  echo "   rozpakowano $n paczek do $arch"
fi

echo "== 5. start stosu"
docker compose up -d
echo
echo "Gotowe. Sprawdź panel (Urd → Zweryfikuj teraz) i stan agentów (Huginn)."
echo "Zdarzenia z ostatnich dni możesz odtworzyć z archiwum: Urd → Odtworzenie."
