#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rejestracja kolektora syslog albo konektora API na VM laboratorium ze
# stacji – uruchamia enroll-service.sh w katalogu stosu na VM (po
# „deploy.sh config” i „deploy.sh collector|connector”). Konektor
# w laboratorium łączy się z symulatorem Microsoft Graph (entrasim).
#
#   deploy/lab/service-enroll.sh collector|connector [grupa agentów]
set -euo pipefail
host="${SIEM_LAB_HOST:-siem@192.168.88.98}"
key="${SIEM_LAB_KEY:-$HOME/.ssh/siem_lab}"
dir="${SIEM_LAB_DIR:-siem-lab}"
ssh -i "$key" -o BatchMode=yes "$host" "VARDR_LAB_ENTRASIM=1 $dir/enroll-service.sh $(printf '%q ' "$@")"
