#!/bin/bash
# Przywrócenie Vardra z kopii zapasowej.
#
#   ./restore.sh <vardr-….tar.gpg> [katalog z paczkami urd-….tar.gpg]
#       odtworzenie na czystej VM (Docker zainstalowany, stos skopiowany:
#       deploy/lab/deploy.sh config + usługi) – wszystko, co jest w kopii;
#       gpg zapyta o hasło kopii (albo plik z hasłem w VARDR_BACKUP_PASS_FILE)
#
#   ./restore.sh --zlecenie
#       przywrócenie zlecone w panelu (Administracja → Kopie zapasowe →
#       Przywracanie); uruchamiane co minutę z crona (deploy.sh config).
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

[ -f docker-compose.yml ] || { echo "uruchom w katalogu stosu (docker-compose.yml)" >&2; exit 2; }

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
restore_by="restore.sh (ręcznie)"
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
      VALUES ('restore', '$by', 'przywrócenie kopii $name (zrzut bazy: ${dumped:-nieznany})', '$name', $from, now())" >/dev/null; then
    log "   archiwum NIS2: zlecono uzgodnienie spisu z plikami zapisanymi po zrzucie (${dumped:-czas zrzutu nieznany})"
  else
    log "   UWAGA: nie udało się zlecić uzgodnienia spisu archiwum – pliki zapisane po zrzucie rozstrzygniesz w panelu (Urd)" >&2
  fi
}

# restore_parts <katalog z rozpakowaną kopią> <części: saga config grafana>
restore_parts() {
  local work="$1"
  shift
  local parts=" $* "
  if [[ $parts == *" config "* ]]; then
    log "== 2. certs/ i .env"
    for f in .env certs; do
      if [ -e "$f" ]; then
        rm -rf "$f.przed-odtworzeniem"
        mv "$f" "$f.przed-odtworzeniem"
      fi
      cp -r "$work/$f" "$f"
    done
    chmod 600 .env
  fi
  [ -f .env ] || { echo "brak .env – bez niego stos nie wystartuje (kopia bez konfiguracji?)" >&2; return 1; }

  if [[ $parts == *" saga "* ]]; then
    log "== 3. baza Saga"
    docker compose stop "${saga_users[@]}" >/dev/null 2>&1 || true
    docker compose up -d saga
    for _ in $(seq 1 60); do
      [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q saga)")" = healthy ] && break
      sleep 2
    done
    docker compose exec -T saga pg_restore -U saga_admin -d saga --clean --if-exists < "$work/saga.dump"
    recovery_request "$work/saga.dump"
  fi

  if [[ $parts == *" grafana "* ]]; then
    log "== 3a. dane Grafany"
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
    log "BŁĄD: niepoprawne zlecenie przywracania" >&2
    exit 1
  fi
  src="${SIEM_BACKUP_DIR:-/srv/vardr/backup}/$file"
  name=$(basename "$file")
  pass_args=(--batch --pinentry-mode loopback --passphrase-file "$HOME/.vardr-backup.pass")
  work="$(mktemp -d)"
  started=$(date -u +%FT%TZ)

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
    log "BŁĄD przywracania: $1" >&2
    docker compose up -d >/dev/null 2>&1 || true
    sleep 10
    finish false "$1"
    rm -rf "$work" "$job.wykonywane"
    exit 1
  }
  trap 'fail "przerwane w kroku: $BASH_COMMAND"' ERR

  restore_by="$by (panel)" restore_name="$name"
  log "== przywracanie z panelu: $name ($parts), zlecił $by"
  [ -f "$src" ] || fail "kopii $name nie ma na serwerze (usunięta przez retencję?)"
  decrypt "$src" | tar -C "$work" -xf - || fail "odszyfrowanie kopii nieudane (hasło kopii?)"
  for p in ${parts//,/ }; do
    [[ " $(parts_in "$work") " == *" $p "* ]] || fail "kopia nie zawiera części $p"
  done
  restore_parts "$work" ${parts//,/ }
  log "== 5. start stosu"
  docker compose up -d
  # Usługi stosujące migracje (panel, detektor, archiwizator) potrzebują chwili.
  for _ in $(seq 1 30); do
    psql_saga -c "SELECT 1 FROM backup_requests LIMIT 1" >/dev/null 2>&1 && break
    sleep 2
  done
  trap - ERR
  msg="przywrócono z $name: ${parts//,/, } ($(date -u +%FT%TZ))"
  [[ ",$parts," == *",saga,"* ]] && msg="$msg – baza jest teraz w stanie z dnia kopii; konta i sesje też, zaloguj się ponownie"
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
  echo "użycie: ./restore.sh <vardr-….tar.gpg> [katalog z paczkami urd-….tar.gpg] | ./restore.sh --zlecenie" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== 1. odszyfrowanie $backup"
decrypt "$backup" | tar -C "$work" -xf -
cat "$work/KOPIA.txt"
if [ -e "$work/saga.dump" ]; then
  docker run --rm -i postgres:18-alpine pg_restore --list < "$work/saga.dump" > /dev/null || {
    echo "kopia bazy nieczytelna" >&2
    exit 1
  }
fi
parts=$(parts_in "$work")

echo
echo "Odtworzenie ZASTĄPI na tym serwerze to, co jest w kopii:"
[[ " $parts " == *" saga "* ]] && echo "  – bazę Saga"
[[ " $parts " == *" config "* ]] && echo "  – certs/ i .env"
[[ " $parts " == *" grafana "* ]] && echo "  – dane Grafany"
read -r -p "Kontynuować? Wpisz TAK: " ok
[ "$ok" = TAK ] || { echo "Przerwano."; exit 1; }

restore_name=$(basename "$backup")
# shellcheck disable=SC2086
restore_parts "$work" $parts

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
