#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Vardr backups – server commands. Backups are made by the siem-backup
# service (backup container) according to the panel settings: Administration
# → Backups (schedule, contents, retention, destination).
#
#   ./backup.sh                     backup now (request for the service; waits for the result)
#   ./backup.sh password init       first backup password – shown ONCE, write it down
#   ./backup.sh password show       shows the current password
#   ./backup.sh password change     new password for further backups (old backups
#                                   open only with the old password)
#   (Polish aliases: haslo init|pokaz|zmien)
#
# Hasło leży w ~/.vardr-backup.pass (instalacja z paczki: VARDR_BACKUP_PASS_FILE
# w .env, /etc/vardr/backup.pass; tylko dla właściciela) – poza katalogiem
# stosu i poza samą kopią; panel go nie zna. Bez hasła kopii NIE DA SIĘ
# odtworzyć: po utracie VM odtworzenie wymaga hasła zapisanego przez
# administratora poza serwerem. Nazwa pliku kopii zawiera identyfikator
# hasła (k + 8 znaków), żeby było wiadomo, którym hasłem ją otworzyć.
#
# Odtworzenie całego systemu na czystej VM: ./restore.sh (docs/en/operations.md).
set -euo pipefail
cd "$(dirname "$0")"
umask 077

pass_file=$(sed -n 's/^VARDR_BACKUP_PASS_FILE=//p' .env 2>/dev/null | tail -1)
pass_file="${pass_file:-$HOME/.vardr-backup.pass}"

key_id() { printf 'k%s' "$(sha256sum "$pass_file" | cut -c1-8)"; }

show_pass() {
  cat <<EOF

  ======================================================================
   VARDR BACKUP PASSWORD

       $(cat "$pass_file")

   Identifier: $(key_id) (it is in the name of every backup file)

   Write it down NOW outside the server (password manager, safe, paper).
   Without it the backups cannot be decrypted – nobody can recover it.
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

if [ "${1:-}" = password ] || [ "${1:-}" = haslo ]; then
  case "${2:-}" in
  init)
    if [ -s "$pass_file" ]; then
      echo "The backup password already exists (./backup.sh password show / change)." >&2
      exit 1
    fi
    new_pass
    show_pass
    ;;
  show | pokaz)
    [ -s "$pass_file" ] || { echo "No password – ./backup.sh password init" >&2; exit 1; }
    show_pass
    ;;
  change | zmien)
    [ -s "$pass_file" ] || { echo "No password – ./backup.sh password init" >&2; exit 1; }
    echo "Existing backups (identifier $(key_id)) can be opened only with the current password."
    read -r -p "Is the current password written down outside the server? Type YES: " ok
    [ "$ok" = YES ] || [ "$ok" = TAK ] || { echo "Aborted – password unchanged."; exit 1; }
    cp -p "$pass_file" "$pass_file.old"
    new_pass
    show_pass
    rm -f "$pass_file.old"
    echo "Further backups will be encrypted with the new password."
    ;;
  *)
    echo "usage: ./backup.sh password init|show|change" >&2
    exit 2
    ;;
  esac
  exit 0
fi

if [ $# -gt 0 ]; then
  echo "usage: ./backup.sh | ./backup.sh password init|show|change" >&2
  exit 2
fi
if [ ! -s "$pass_file" ]; then
  echo "ERROR: no backup password – first run ./backup.sh password init" >&2
  exit 1
fi
exec docker compose exec -T backup siem-backup run
