#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Import reguł SigmaHQ na serwerze z instalacji (install.sh) – odpowiednik
# procedury z docs/reguly.md („Import reguł SigmaHQ”) bez repozytorium Vardra.
#
#   sudo ./sigmahq-import.sh            pobranie/aktualizacja reguł SigmaHQ
#   sudo ./sigmahq-import.sh --remove   usunięcie reguł SigmaHQ z serwera
#
# Reguły dla zbieranych źródeł trafiają do rules/<wersja>/sigmahq, te
# z parserem Vardra niezgodne są pomijane, a wszystkie zaimportowane są
# WYŁĄCZONE – włącza się je w panelu (Reguły, filtr SigmaHQ, najlepiej przez
# tryb próbny). Włączenia z panelu zostają przy aktualizacji (zapisane po id
# reguły). Nowa wersja katalogu reguł jest przełączana atomowo, detektor
# wczytuje ją w ciągu 30 s. Aktualizacja Vardra (install.sh) przenosi
# zaimportowane reguły do nowej wersji.
#
# Reguły SigmaHQ: https://github.com/SigmaHQ/sigma, licencja Detection Rule
# License (DRL) 1.1 – autorzy reguł są widoczni w panelu przy regule i alercie.
set -euo pipefail
cd "$(dirname "$0")"
umask 022

[ "$(id -u)" = 0 ] || { echo "uruchom jako root (sudo $0)" >&2; exit 1; }
[ -L rules/current ] || { echo "brak rules/current – uruchom w katalogu instalacji Vardra" >&2; exit 1; }
env_get() { sed -n "s/^$1=//p" .env | tail -1; }
owner="$(env_get VARDR_UID):$(env_get VARDR_GID)"

# Kategorie dla źródeł, które Vardr zbiera (agent Windows, Entra ID).
dirs="windows/process_creation windows/powershell/powershell_script windows/builtin/security windows/builtin/system
windows/builtin/windefend windows/network_connection windows/file/file_event windows/dns_query windows/registry/registry_set
cloud/azure/signin_logs cloud/azure/audit_logs"

bad=""
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Nazwa nowej wersji – unikalna także przy dwóch uruchomieniach w tej samej sekundzie.
new="v$(date +%Y%m%d%H%M%S)"
while [ -e "rules/$new" ]; do sleep 1; new="v$(date +%Y%m%d%H%M%S)"; done
mkdir -p "$work/$new"
cp -a rules/current/. "$work/$new/"
rm -rf "$work/$new/sigmahq"

if [ "${1:-}" != --remove ]; then
  echo "== pobieranie SigmaHQ (github.com/SigmaHQ/sigma)"
  curl -fsSL https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master | tar -xz -C "$work"
  src="$work/sigma-master"
  for d in $dirs; do
    [ -d "$src/rules/$d" ] || continue
    mkdir -p "$work/$new/sigmahq/$d"
    cp -r "$src/rules/$d/." "$work/$new/sigmahq/$d/"
  done
  # Tylko reguły stabilne i testowe (bez experimental, deprecated, unsupported).
  grep -rlE '^status: (experimental|deprecated|unsupported)' "$work/$new/sigmahq" | xargs -r rm
  echo "== sprawdzenie parserem Vardra"
  bin/siem-detector check "$work/$new" > "$work/check.txt" 2>&1 || true
  bad=$(sed -nE 's/^BŁĄD +(sigmahq\/[^:]+\.ya?ml):.*/\1/p' "$work/check.txt" | sort -u)
  # shellcheck disable=SC2086
  [ -z "$bad" ] || (cd "$work/$new" && echo "$bad" | xargs -r rm -f)
  # Wszystkie wyłączone w plikach – inaczej włączyłyby się setki reguł naraz.
  find "$work/$new/sigmahq" -name '*.yml' -exec sh -c 'printf "\nvardr:\n  enabled: false\n" >> "$1"' _ {} \;
  cp "$src/LICENSE" "$work/$new/sigmahq/LICENSE.SigmaHQ.md" 2>/dev/null || true
  cat > "$work/$new/sigmahq/README.md" <<EOF
# Reguły SigmaHQ

Reguły z https://github.com/SigmaHQ/sigma (import $(date -I), sigmahq-import.sh),
licencja Detection Rule License (DRL) 1.1: https://github.com/SigmaHQ/Detection-Rule-License
Autorzy każdej reguły – pole \`author\` w pliku (widoczne w panelu przy regule i alercie).
EOF
fi

if ! bin/siem-detector check "$work/$new" > "$work/check.txt" 2>&1; then
  grep -m 20 -E '^BŁĄD' "$work/check.txt" >&2 || true
  echo "BŁĄD: nowy zestaw reguł nie przechodzi sprawdzenia – nic nie zmieniono" >&2
  exit 1
fi

mv "$work/$new" "rules/$new"
chown -R "$owner" "rules/$new"
ln -sfn "$new" rules/current.tmp && mv -T rules/current.tmp rules/current
chown -h "$owner" rules/current
find rules -mindepth 1 -maxdepth 1 -type d -name 'v*' | sort | head -n -3 | xargs -r rm -rf

n=$(find "rules/$new/sigmahq" -name '*.yml' 2>/dev/null | wc -l || true)
if [ "${1:-}" = --remove ]; then
  echo "Reguły SigmaHQ usunięte (wersja reguł $new)."
else
  echo "Zaimportowano $n reguł SigmaHQ (wyłączone, wersja reguł $new; pominięte niezgodne: $(echo "$bad" | grep -c . || true))."
  echo "Detektor wczyta je w ciągu 30 s. Włączanie: panel → Reguły, filtr SigmaHQ (najlepiej przez tryb próbny)."
fi
