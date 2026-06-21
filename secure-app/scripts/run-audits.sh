#!/usr/bin/env bash
# Week 6 Task 1 — runs the three audit tools listed in the brief and writes
# raw output under reports/raw/<tool>/.
#
# Usage:
#   ./scripts/run-audits.sh [target_url]
#
# Each tool runs independently; failures don't block the others. The script
# uses sudo only for Lynis (host audit). If you don't have sudo, comment it.

set -uo pipefail

TARGET="${1:-http://localhost:3000}"
RAW_DIR="../../reports/raw"
mkdir -p "${RAW_DIR}/zap" "${RAW_DIR}/nikto" "${RAW_DIR}/lynis"

echo "===== [1/3] OWASP ZAP baseline scan against ${TARGET} ====="
# Headless baseline scan via the official Docker image. Won't actively
# attack; it crawls + checks for common misconfigs.
if command -v docker >/dev/null; then
  docker run --rm -t \
    -v "$(pwd)/${RAW_DIR}/zap:/zap/wrk/:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t "${TARGET}" \
                    -r zap-report.html \
                    -J zap-report.json \
                    -w zap-report.md \
    || echo "[!] ZAP exited non-zero (findings or crawl issues — check report)."
else
  echo "[!] docker not available — install OWASP ZAP locally and run:"
  echo "    zap.sh -cmd -quickurl ${TARGET} -quickout ${RAW_DIR}/zap/zap-report.html"
fi

echo
echo "===== [2/3] Nikto against ${TARGET} ====="
if command -v nikto >/dev/null; then
  nikto -h "${TARGET}" -o "${RAW_DIR}/nikto/nikto-report.html" -Format htm \
    || echo "[!] Nikto exited non-zero (findings present — check report)."
else
  echo "[!] nikto not installed. apt install nikto"
fi

echo
echo "===== [3/3] Lynis host audit ====="
if command -v lynis >/dev/null; then
  sudo lynis audit system --quiet --report-file "${RAW_DIR}/lynis/lynis-report.dat" \
    || echo "[!] Lynis returned warnings — that's expected on first run."
  sudo cp /var/log/lynis.log "${RAW_DIR}/lynis/lynis.log" 2>/dev/null || true
else
  echo "[!] lynis not installed. apt install lynis"
fi

echo
echo "[*] Raw output in ${RAW_DIR}/."
echo "[*] Now translate findings into reports/security-audit-report.md."
