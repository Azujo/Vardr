#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Restoring Vardr from a backup.
#
#   ./restore.sh <vardr-….tar.gpg> [directory with urd-….tar.gpg packages]
#       restore on a clean VM (Docker installed, stack copied:
#       deploy/lab/deploy.sh config + services or install.sh from the Vardr
#       bundle) – everything that is in the backup;
#       gpg asks for the backup password (or the file in VARDR_BACKUP_PASS_FILE)
#
#   ./restore.sh --zlecenie
#       restore requested in the panel (Administration → Backups → Restore);
#       run every minute by cron (deploy.sh config) or the systemd timer
#       vardr-restore.timer (install.sh).
#
# Messages are printed in English; texts stored for the panel follow the
# system language (panel → Notifications → System language).
#
#       Usługa kopii przygotowuje zlecenie (kopia obecnego stanu, pobranie
#       i sprawdzenie kopii) w <kopie>/.przywracanie/zlecenie; skrypt
#       przywraca wybrane części, bo tylko on może zatrzymać usługi.
#
# Kroki:
#   1. odszyfrowanie kopii,
#   2. certs/ i .env do katalogu stosu (poprzednie zostają z rozszerzeniem
#      .przed-odtworzeniem),
#   3. baza Saga: pg_restore przy zatrzymanych usługach, które z niej korzystają
#      (konta, agenci, certyfikaty, grupy, alerty, spis archiwum NIS2, polityki,
#      kanały powiadomień, ustawienia kopii),
#   3a. dane Grafany,
#   4. opcjonalnie archiwum NIS2: paczki urd-… po kolei do SIEM_ARCHIVE_PATH,
#   5. start całego stosu.
#
# Czego kopia nie zawiera: zdarzeń w ClickHouse (kilka dni, odtwarzalne
# z archiwum – panel → Urd → Odtworzenie) i kolejek NATS (agenci dosyłają
# zaległe zdarzenia sami).
set -euo pipefail
cd "$(dirname "$0")"
umask 077

[ -f docker-compose.yml ] || { echo "run in the stack directory (docker-compose.yml)" >&2; exit 2; }

pass_args=()
pass_file="${VARDR_BACKUP_PASS_FILE:-${HEIMDALL_BACKUP_PASS_FILE:-}}"  # HEIMDALL_: dawna nazwa zmiennej
if [ -n "$pass_file" ]; then
  pass_args=(--batch --pinentry-mode loopback --passphrase-file "$pass_file")
fi
decrypt() { gpg --quiet "${pass_args[@]}" --decrypt "$1"; }
log() { echo "$(date -u +%FT%TZ) $*"; }

# Usługi korzystające z bazy Saga – zatrzymane na czas pg_restore.
saga_users=(api detector archiver backup)

# Kto i z jakiej kopii przywraca (wpis w spisie archiwum).
restore_by="restore.sh (manual)"
restore_name=""

# recovery_request <saga.dump>: spis archiwum NIS2 wraca do chwili zrzutu,
# a segmenty i manifesty zapisane później zostają na dysku bez wpisu.
# Zlecenie dla archiwizatora (urd.recoveries): przy starcie przyjmie do spisu
# pliki utworzone od zrzutu (10 min zapasu – segment otwarty przed zrzutem)
# do teraz, po sprawdzeniu sum i łańcucha; reszta – decyzja w panelu.
recovery_request() {
  local dumped from by name
  dumped=$(docker compose exec -T saga pg_restore --list < "$1" | sed -n 's/^;[[:space:]]*Archive created at //p' | head -1 || true)
  dumped=${dumped//\'/}
  from=NULL
  [ -n "$dumped" ] && from="('$dumped'::timestamptz - interval '10 minutes')"
  by=${restore_by//\'/\'\'}
  name=${restore_name//\'/\'\'}
  if psql_saga -c "INSERT INTO urd.recoveries (kind, requested_by, reason, backup, window_from, window_to)
      VALUES ('restore', '$by', '$(t "przywrócenie kopii $name (zrzut bazy: ${dumped:-nieznany})" "restore of backup $name (database dump: ${dumped:-unknown})")', '$name', $from, now())" >/dev/null; then
    log "   NIS2 archive: catalog reconciliation requested for files written after the dump (${dumped:-dump time unknown})"
  else
    log "   WARNING: could not request archive catalog reconciliation – decide on files written after the dump in the panel (Urd)" >&2
  fi
}

# restore_parts <katalog z rozpakowaną kopią> <części: saga config grafana>
restore_parts() {
  local work="$1"
  shift
  local parts=" $* "
  if [[ $parts == *" config "* ]]; then
    log "== 2. certs/ and .env"
    for f in .env certs; do
      if [ -e "$f" ]; then
        rm -rf "$f.przed-odtworzeniem"
        mv "$f" "$f.przed-odtworzeniem"
      fi
      cp -r "$work/$f" "$f"
    done
    chmod 600 .env
  fi
  [ -f .env ] || { echo "no .env – the stack will not start without it (backup without configuration?)" >&2; return 1; }

  if [[ $parts == *" saga "* ]]; then
    log "== 3. Saga database"
    docker compose stop "${saga_users[@]}" >/dev/null 2>&1 || true
    docker compose up -d saga
    for _ in $(seq 1 60); do
      [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q saga)")" = healthy ] && break
      sleep 2
    done
    docker compose exec -T saga pg_restore -U saga_admin -d saga --clean --if-exists < "$work/saga.dump"
    SYSLANG=$(syslang)
    recovery_request "$work/saga.dump"
  fi

  if [[ $parts == *" grafana "* ]]; then
    log "== 3a. Grafana data"
    docker compose stop grafana >/dev/null 2>&1 || true
    docker compose run --rm --no-deps -T --user 0 --entrypoint sh grafana \
      -c 'find /var/lib/grafana -mindepth 1 -maxdepth 1 ! -name dashboards -exec rm -rf {} + && tar -C /var/lib/grafana -xf - && find /var/lib/grafana -mindepth 1 -maxdepth 1 ! -name dashboards -exec chown -R 472:0 {} +' < "$work/grafana.tar"
  fi
}

# Części obecne w rozpakowanej kopii.
parts_in() {
  local w="$1" p=()
  [ -e "$w/.env" ] && p+=(config)
  [ -e "$w/saga.dump" ] && p+=(saga)
  [ -e "$w/grafana.tar" ] && p+=(grafana)
  echo "${p[*]}"
}

psql_saga() { docker compose exec -T saga psql -U saga_admin -d saga -At -v ON_ERROR_STOP=1 "$@"; }

# Język systemu (ustawienie w panelu) – teksty zapisywane w Sadze dla panelu.
syslang() { [ "$(psql_saga -c "SELECT language FROM system_language" 2>/dev/null)" = en ] && echo en || echo pl; }
t() { if [ "${SYSLANG:-pl}" = en ]; then echo "$2"; else echo "$1"; fi; }

# ---- zlecenie z panelu ----
if [ "${1:-}" = --zlecenie ]; then
  set -E # pułapka ERR także w funkcjach
  set -a
  . ./.env
  set +a
  jobdir="${SIEM_BACKUP_DIR:-/srv/vardr/backup}/.przywracanie"
  job="$jobdir/zlecenie"
  [ -f "$job" ] || exit 0
  exec 9> "$jobdir/.blokada"
  flock -n 9 || exit 0
  [ -f "$job" ] || exit 0
  field() { grep -m1 "^$1=" "$job" | cut -d= -f2-; }
  id=$(field id) file=$(field file) parts=$(field parts) by=$(field by)
  mv "$job" "$job.wykonywane"
  if ! [[ $id =~ ^[0-9]+$ && $file =~ ^(\.przywracanie/)?(vardr|heimdall)-[0-9]{8}-[0-9]{4}-k[0-9a-f]{8}\.tar\.gpg$ && $parts =~ ^(saga|config|grafana)(,(saga|config|grafana))*$ ]]; then
    log "ERROR: invalid restore request" >&2
    exit 1
  fi
  src="${SIEM_BACKUP_DIR:-/srv/vardr/backup}/$file"
  name=$(basename "$file")
  pass_args=(--batch --pinentry-mode loopback --passphrase-file "${VARDR_BACKUP_PASS_FILE:-$HOME/.vardr-backup.pass}")
  work="$(mktemp -d)"
  started=$(date -u +%FT%TZ)
  SYSLANG=$(syslang)

  # Wynik w Sadze: po przywróceniu bazy zlecenia już w niej nie ma (baza
  # z dnia kopii) – wpis powstaje od nowa; inaczej zlecenie jest zamykane.
  finish() {
    local ok="$1" msg="$2"
    msg=${msg//\'/\'\'}
    if [[ ",$parts," == *",saga,"* ]] && [ "$ok" = true ]; then
      psql_saga -c "INSERT INTO backup_requests (action, requested_by, requested_at, started_at, done_at, ok, message, params)
        VALUES ('restore', '$by', '$started', '$started', now(), true, '$msg',
        jsonb_build_object('name', '$name', 'parts', string_to_array('$parts', ',')))" >/dev/null || true
    else
      psql_saga -c "UPDATE backup_requests SET done_at = now(), ok = $ok, message = '$msg' WHERE id = $id" >/dev/null || true
    fi
  }
  fail() {
    log "restore ERROR: $1" >&2
    docker compose up -d >/dev/null 2>&1 || true
    sleep 10
    finish false "$1"
    rm -rf "$work" "$job.wykonywane"
    exit 1
  }
  trap 'fail "$(t "przerwane w kroku" "interrupted at step"): $BASH_COMMAND"' ERR

  restore_by="$by (panel)" restore_name="$name"
  log "== restore requested in the panel: $name ($parts), by $by"
  [ -f "$src" ] || fail "$(t "kopii $name nie ma na serwerze (usunięta przez retencję?)" "backup $name is not on the server (removed by retention?)")"
  decrypt "$src" | tar -C "$work" -xf - || fail "$(t "odszyfrowanie kopii nieudane (hasło kopii?)" "decrypting the backup failed (backup password?)")"
  for p in ${parts//,/ }; do
    [[ " $(parts_in "$work") " == *" $p "* ]] || fail "$(t "kopia nie zawiera części $p" "the backup does not contain part $p")"
  done
  restore_parts "$work" ${parts//,/ }
  log "== 5. starting the stack"
  docker compose up -d
  # Usługi stosujące migracje (panel, detektor, archiwizator) potrzebują chwili.
  for _ in $(seq 1 30); do
    psql_saga -c "SELECT 1 FROM backup_requests LIMIT 1" >/dev/null 2>&1 && break
    sleep 2
  done
  trap - ERR
  msg="$(t "przywrócono z" "restored from") $name: ${parts//,/, } ($(date -u +%FT%TZ))"
  [[ ",$parts," == *",saga,"* ]] && msg="$msg – $(t "baza jest teraz w stanie z dnia kopii; konta i sesje też, zaloguj się ponownie" "the database is now as on the backup date; accounts and sessions too, sign in again")"
  finish true "$msg"
  rm -rf "$work" "$job.wykonywane"
  # Kopia pobrana z miejsca docelowego nie jest już potrzebna.
  [[ $file == .przywracanie/* ]] && rm -f "$src"
  log "$msg"
  exit 0
fi

# ---- odtworzenie ręczne ----
backup="${1:-}"
urd_dir="${2:-}"
if [ -z "$backup" ] || [ ! -f "$backup" ]; then
  echo "usage: ./restore.sh <vardr-….tar.gpg> [directory with urd-….tar.gpg packages] | ./restore.sh --zlecenie" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== 1. decrypting $backup"
decrypt "$backup" | tar -C "$work" -xf -
cat "$work/KOPIA.txt"
if [ -e "$work/saga.dump" ]; then
  docker run --rm -i postgres:18-alpine pg_restore --list < "$work/saga.dump" > /dev/null || {
    echo "the database backup is unreadable" >&2
    exit 1
  }
fi
parts=$(parts_in "$work")

echo
echo "The restore will REPLACE on this server what is in the backup:"
[[ " $parts " == *" saga "* ]] && echo "  – the Saga database"
[[ " $parts " == *" config "* ]] && echo "  – certs/ and .env"
[[ " $parts " == *" grafana "* ]] && echo "  – Grafana data"
read -r -p "Continue? Type YES: " ok
[ "$ok" = YES ] || [ "$ok" = TAK ] || { echo "Aborted."; exit 1; }

restore_name=$(basename "$backup")
# shellcheck disable=SC2086
restore_parts "$work" $parts

if [ -n "$urd_dir" ]; then
  echo "== 4. NIS2 archive"
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
  echo "   extracted $n packages to $arch"
fi

echo "== 5. starting the stack"
docker compose up -d
echo
echo "Done. Check the panel (Urd → Verify now) and the agent state (Huginn)."
echo "Events from the last days can be replayed from the archive: Urd → Replay."
