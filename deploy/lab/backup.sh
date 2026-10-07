#!/bin/bash
# Kopia zapasowa stosu laboratoryjnego (uruchamiana z crona użytkownika siem):
#   - baza Saga (konta, agenci, certyfikaty, grupy, spis archiwum NIS2) – pg_dump,
#   - konfiguracja i klucze: certs/ (w tym klucz CA agentów) oraz .env.
# Archiwum NIS2 nie jest kopiowane (to setki GB); jego spis jest w bazie,
# a manifesty także na dysku archiwum.
#
# Katalog kopii: SIEM_BACKUP_DIR (domyślnie /srv/heimdall/backup, gdy istnieje,
# inaczej ~/backup). Kopie są tylko dla właściciela (zawierają hasła i klucze).
# Czas ostatniej udanej kopii trafia do metryki node-exportera
# (heimdall_backup_last_success_timestamp_seconds) – na niej opiera się alert.
#
# Odtworzenie bazy (na pustej bazie saga, jako saga_admin):
#   docker compose exec -T saga pg_restore -U saga_admin -d saga --clean --if-exists < saga-….dump
set -euo pipefail
cd "$(dirname "$0")"
umask 077

default_dir="$HOME/backup"
[ -d /srv/heimdall/backup ] && [ -w /srv/heimdall/backup ] && default_dir=/srv/heimdall/backup
dir="${SIEM_BACKUP_DIR:-$default_dir}"
keep_days="${SIEM_BACKUP_KEEP_DAYS:-14}"
stamp="$(date -u +%Y%m%d-%H%M)"
mkdir -p "$dir" metrics
chmod 755 metrics # czyta node-exporter

dump="$dir/saga-$stamp.dump"
docker compose exec -T saga pg_dump -U saga_admin -d saga --format=custom > "$dump.tmp"
# Kopia, której nie da się odczytać, nie jest kopią.
docker compose exec -T saga pg_restore --list < "$dump.tmp" > /dev/null
mv "$dump.tmp" "$dump"

tar -cf "$dir/config-$stamp.tar" certs .env

find "$dir" -maxdepth 1 \( -name 'saga-*.dump' -o -name 'config-*.tar' \) -mtime +"$keep_days" -delete

cat > metrics/backup.prom.tmp <<EOF
# HELP heimdall_backup_last_success_timestamp_seconds Czas ostatniej udanej kopii zapasowej.
# TYPE heimdall_backup_last_success_timestamp_seconds gauge
heimdall_backup_last_success_timestamp_seconds $(date +%s)
# HELP heimdall_backup_size_bytes Rozmiar ostatniej kopii bazy Saga.
# TYPE heimdall_backup_size_bytes gauge
heimdall_backup_size_bytes $(stat -c %s "$dump")
EOF
chmod 644 metrics/backup.prom.tmp
mv metrics/backup.prom.tmp metrics/backup.prom
echo "$(date -u +%FT%TZ) kopia gotowa: $dump ($(du -h "$dump" | cut -f1)), katalog $dir"
