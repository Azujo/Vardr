#!/bin/bash
# Kopie zapasowe Vardra – polecenia serwera. Kopie wykonuje usługa
# siem-backup (kontener backup) według ustawień z panelu: Administracja →
# Kopie zapasowe (harmonogram, zawartość, retencja, miejsce docelowe).
#
#   ./backup.sh                 kopia teraz (zlecenie dla usługi; czeka na wynik)
#   ./backup.sh haslo init      pierwsze hasło kopii – pokazywane RAZ, zapisz je
#   ./backup.sh haslo pokaz     pokazuje obecne hasło
#   ./backup.sh haslo zmien     nowe hasło dla kolejnych kopii (stare kopie
#                               otwiera tylko stare hasło)
#
# Hasło leży w ~/.vardr-backup.pass (instalacja z paczki: VARDR_BACKUP_PASS_FILE
# w .env, /etc/vardr/backup.pass; tylko dla właściciela) – poza katalogiem
# stosu i poza samą kopią; panel go nie zna. Bez hasła kopii NIE DA SIĘ
# odtworzyć: po utracie VM odtworzenie wymaga hasła zapisanego przez
# administratora poza serwerem. Nazwa pliku kopii zawiera identyfikator
# hasła (k + 8 znaków), żeby było wiadomo, którym hasłem ją otworzyć.
#
# Odtworzenie całego systemu na czystej VM: ./restore.sh (docs/operacje.md).
set -euo pipefail
cd "$(dirname "$0")"
umask 077

pass_file=$(sed -n 's/^VARDR_BACKUP_PASS_FILE=//p' .env 2>/dev/null | tail -1)
pass_file="${pass_file:-$HOME/.vardr-backup.pass}"

key_id() { printf 'k%s' "$(sha256sum "$pass_file" | cut -c1-8)"; }

show_pass() {
  cat <<EOF

  ======================================================================
   HASŁO KOPII ZAPASOWYCH VARDRA

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

if [ $# -gt 0 ]; then
  echo "użycie: ./backup.sh | ./backup.sh haslo init|pokaz|zmien" >&2
  exit 2
fi
if [ ! -s "$pass_file" ]; then
  echo "BŁĄD: brak hasła kopii – najpierw ./backup.sh haslo init" >&2
  exit 1
fi
exec docker compose exec -T backup siem-backup run
