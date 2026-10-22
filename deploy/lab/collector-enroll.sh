#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rejestracja kolektora syslog – zob. service-enroll.sh.
#   deploy/lab/collector-enroll.sh [grupa agentów]
exec "$(dirname "$0")/service-enroll.sh" collector "$@"
