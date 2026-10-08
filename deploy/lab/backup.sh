#!/bin/bash
# Kopia zapasowa stosu laboratoryjnego (cron użytkownika siem, codziennie 02:15).
#
#   ./backup.sh                 kopia: baza Saga (pg_dump), certs/ (w tym klucz CA
#                               agentów) i .env w jednej paczce zaszyfrowanej gpg
#                               (AES-256); potem wysyłka poza VM, jeśli ustawiona
#   ./backup.sh haslo init      pierwsze hasło kopii – pokazywane RAZ, zapisz je
#   ./backup.sh haslo pokaz     pokazuje obecne hasło
#   ./backup.sh haslo zmien     nowe hasło dla kolejnych kopii (stare kopie
#                               otwiera tylko stare hasło)
#
# Hasło leży w ~/.heimdall-backup.pass (tylko dla właściciela) – poza katalogiem
# stosu i poza samą kopią. Bez hasła kopii NIE DA SIĘ odtworzyć: po utracie VM
# odtworzenie wymaga hasła zapisanego przez administratora poza serwerem.
# Nazwa pliku kopii zawiera identyfikator hasła (k + 8 znaków), żeby było
# wiadomo, którym hasłem ją otworzyć.
#
# Wysyłka poza VM (zmienne w .env):
#   SIEM_BACKUP_REMOTE            np. heimdall@192.168.88.180:/mnt/HDD/TANK/heimdall_backup
#   SIEM_BACKUP_SSH_KEY           klucz SSH (domyślnie ~/.ssh/heimdall_backup)
#   SIEM_BACKUP_REMOTE_KEEP_DAYS  ile dni trzymać kopie na serwerze kopii (90)
# Na serwer trafiają: config/ – zaszyfrowane kopie, urd/ – przyrosty archiwum
# NIS2 (nowe segmenty i manifesty od poprzedniej wysyłki, tar zaszyfrowany tym
# samym hasłem). Nic nie wychodzi z VM w postaci jawnej.
#
# Odtworzenie całego systemu na czystej VM: ./restore.sh (opis w README).
set -euo pipefail
cd "$(dirname "$0")"
umask 077

pass_file="$HOME/.heimdall-backup.pass"

key_id() { printf 'k%s' "$(sha256sum "$pass_file" | cut -c1-8)"; }

show_pass() {
  cat <<EOF

  ======================================================================
   HASŁO KOPII ZAPASOWYCH HEIMDALLA

       $(cat "$pass_file")

   Identyfikator: $(key_id) (jest w nazwie każdego pliku kopii)

   Zapisz je TERAZ poza serwerem (menedżer haseł, sejf, kartka).
   Bez niego kopii nie da się odszyfrować – nikt go nie odtworzy.
  ======================================================================

EOF
}

new_pass() {
  # 32 znaki z bezpiecznego alfabetu (bez znaków mylących: 0/O, 1/l/I).
  local p=""
  while [ ${#p} -lt 32 ]; do
    p+=$(openssl rand -base64 48 | LC_ALL=C tr -dc 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')
  done
  p=${p:0:32}
  printf '%s' "$p" > "$pass_file.tmp"
  chmod 600 "$pass_file.tmp"
  mv "$pass_file.tmp" "$pass_file"
}

if [ "${1:-}" = haslo ]; then
  case "${2:-}" in
  init)
    if [ -s "$pass_file" ]; then
      echo "Hasło kopii już istnieje (./backup.sh haslo pokaz / zmien)." >&2
      exit 1
    fi
    new_pass
    show_pass
    ;;
  pokaz)
    [ -s "$pass_file" ] || { echo "Brak hasła – ./backup.sh haslo init" >&2; exit 1; }
    show_pass
    ;;
  zmien)
    [ -s "$pass_file" ] || { echo "Brak hasła – ./backup.sh haslo init" >&2; exit 1; }
    echo "Dotychczasowe kopie (identyfikator $(key_id)) da się otworzyć tylko obecnym hasłem."
    read -r -p "Czy obecne hasło jest zapisane poza serwerem? Wpisz TAK: " ok
    [ "$ok" = TAK ] || { echo "Przerwano – hasło bez zmian."; exit 1; }
    cp -p "$pass_file" "$pass_file.old"
    new_pass
    show_pass
    rm -f "$pass_file.old"
    echo "Kolejne kopie będą szyfrowane nowym hasłem."
    ;;
  *)
    echo "użycie: ./backup.sh haslo init|pokaz|zmien" >&2
    exit 2
    ;;
  esac
  exit 0
fi

if [ ! -s "$pass_file" ]; then
  echo "$(date -u +%FT%TZ) BŁĄD: brak hasła kopii – administrator musi uruchomić ./backup.sh haslo init" >&2
  exit 1
fi

set -a
. ./.env
set +a
default_dir="$HOME/backup"
[ -d /srv/heimdall/backup ] && [ -w /srv/heimdall/backup ] && default_dir=/srv/heimdall/backup
dir="${SIEM_BACKUP_DIR:-$default_dir}"
keep_days="${SIEM_BACKUP_KEEP_DAYS:-14}"
stamp="$(date -u +%Y%m%d-%H%M)"
kid="$(key_id)"
mkdir -p "$dir" metrics
chmod 755 metrics # czyta node-exporter
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

encrypt() { gpg --batch --quiet --yes --pinentry-mode loopback --passphrase-file "$pass_file" \
  --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 "$@"; }

# 1. Baza Saga – sprawdzona przed zaszyfrowaniem (kopia, której nie da się
#    odczytać, nie jest kopią).
docker compose exec -T saga pg_dump -U saga_admin -d saga --format=custom > "$work/saga.dump"
docker compose exec -T saga pg_restore --list < "$work/saga.dump" > /dev/null
cp -r certs .env "$work/"
cat > "$work/KOPIA.txt" <<EOF
Kopia Heimdalla z $(date -u +%FT%TZ), serwer $(hostname), identyfikator hasła $kid.
Zawartość: saga.dump (pg_dump --format=custom), certs/, .env.
Odtworzenie: ./restore.sh (README, sekcja Kopie zapasowe).
EOF
out="$dir/heimdall-$stamp-$kid.tar.gpg"
tar -C "$work" -cf - saga.dump certs .env KOPIA.txt | encrypt --output "$out.tmp"
mv "$out.tmp" "$out"
size=$(stat -c %s "$out")

# Kopie starego formatu (jawne) i stare kopie lokalne.
find "$dir" -maxdepth 1 \( -name 'saga-*.dump' -o -name 'config-*.tar' -o -name 'heimdall-*.tar.gpg' \) -mtime +"$keep_days" -delete

metric() {
  local tmp=metrics/backup.prom.tmp
  {
    echo "# HELP heimdall_backup_last_success_timestamp_seconds Czas ostatniej udanej kopii zapasowej."
    echo "# TYPE heimdall_backup_last_success_timestamp_seconds gauge"
    echo "heimdall_backup_last_success_timestamp_seconds $(date +%s)"
    echo "# HELP heimdall_backup_size_bytes Rozmiar ostatniej kopii (zaszyfrowanej)."
    echo "# TYPE heimdall_backup_size_bytes gauge"
    echo "heimdall_backup_size_bytes $size"
    if [ -n "${remote_ok:-}" ]; then
      echo "# HELP heimdall_backup_remote_last_success_timestamp_seconds Czas ostatniej udanej wysyłki kopii poza VM."
      echo "# TYPE heimdall_backup_remote_last_success_timestamp_seconds gauge"
      echo "heimdall_backup_remote_last_success_timestamp_seconds $remote_ok"
    elif [ -f metrics/backup-remote.last ]; then
      echo "heimdall_backup_remote_last_success_timestamp_seconds $(cat metrics/backup-remote.last)"
    fi
  } > "$tmp"
  chmod 644 "$tmp"
  mv "$tmp" metrics/backup.prom
}
metric
echo "$(date -u +%FT%TZ) kopia gotowa: $out ($(du -h "$out" | cut -f1)), hasło $kid"

# 2. Wysyłka poza VM.
[ -n "${SIEM_BACKUP_REMOTE:-}" ] || exit 0
ssh_key="${SIEM_BACKUP_SSH_KEY:-$HOME/.ssh/heimdall_backup}"
remote_keep="${SIEM_BACKUP_REMOTE_KEEP_DAYS:-90}"
host="${SIEM_BACKUP_REMOTE%%:*}"
rdir="${SIEM_BACKUP_REMOTE#*:}"
rssh() { ssh -i "$ssh_key" -o BatchMode=yes -o ConnectTimeout=15 "$host" "$@"; }
rssh "mkdir -p '$rdir/config' '$rdir/urd'"
rsync -a --ignore-existing -e "ssh -i $ssh_key -o BatchMode=yes" "$out" "$host:$rdir/config/"

# Archiwum NIS2: tylko pliki, których jeszcze nie wysłano (segmenty się nie
# zmieniają). Lista wysłanych w $dir/urd-sent.list.
arch="${SIEM_ARCHIVE_PATH:-./archive}"
sent="$dir/urd-sent.list"
touch "$sent"
if [ -d "$arch/segments" ]; then
  (cd "$arch" && find segments manifests -type f 2>/dev/null | LC_ALL=C sort) > "$work/now.list"
  LC_ALL=C comm -23 "$work/now.list" <(LC_ALL=C sort -u "$sent") > "$work/new.list"
  n=$(wc -l < "$work/new.list")
  # Znacznik katalogu archiwum w każdej paczce (starsze paczki mogą wygasnąć).
  [ -f "$arch/.urd-archive" ] && echo .urd-archive >> "$work/new.list"
  if [ "$n" -gt 0 ]; then
    batch="urd-$stamp-$kid.tar.gpg"
    tar -C "$arch" -cf - -T "$work/new.list" | encrypt --output "$work/$batch"
    rsync -a -e "ssh -i $ssh_key -o BatchMode=yes" "$work/$batch" "$host:$rdir/urd/$batch.tmp"
    rssh "mv '$rdir/urd/$batch.tmp' '$rdir/urd/$batch'"
    # Wysłane = to, co jest teraz (pliki usunięte po retencji wypadają z listy).
    cp "$work/now.list" "$sent"
    echo "$(date -u +%FT%TZ) archiwum: wysłano $n plików ($(du -h "$work/$batch" | cut -f1) zaszyfrowane)"
  fi
fi
rssh "find '$rdir/config' '$rdir/urd' -maxdepth 1 -name '*.tar.gpg' -mtime +$remote_keep -delete"
remote_ok=$(date +%s)
echo "$remote_ok" > metrics/backup-remote.last
metric
echo "$(date -u +%FT%TZ) wysłano na $host:$rdir"
