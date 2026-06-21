#!/usr/bin/env bash
# Week 5 Task 2 — SQLMap runner.
#
# Targets the login form (the textbook injection point in the week-2
# vulnerable-app). The week3+ code uses better-sqlite3 prepared statements,
# so we EXPECT sqlmap to find nothing on the secure-app. Run it anyway and
# attach the report — "no vulnerabilities found" is the deliverable.
#
# Requires Kali or any host with sqlmap installed (`apt install sqlmap`).

set -euo pipefail

TARGET="${1:-http://localhost:3000}"
OUT_DIR="${2:-../../reports/sqlmap}"

mkdir -p "${OUT_DIR}"

echo "[*] Running sqlmap against ${TARGET}/login (POST username,password)..."
sqlmap \
  -u "${TARGET}/login" \
  --data="username=admin&password=test&_csrf=BYPASSED" \
  --method=POST \
  --batch \
  --random-agent \
  --level=3 --risk=2 \
  --output-dir="${OUT_DIR}" \
  --flush-session \
  | tee "${OUT_DIR}/sqlmap.log"

echo
echo "[*] Done. Summary in ${OUT_DIR}/sqlmap.log"
echo "[*] If the line 'all tested parameters do not appear to be injectable'"
echo "    appears at the bottom, the fix held. Paste that excerpt into"
echo "    reports/ethical-hacking-report.md → SQLi section."
