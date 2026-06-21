#!/usr/bin/env bash
# Smoke test for the in-app alert engine + Fail2Ban filter (Week 4 Task 1).
# Hits /login with bad credentials enough times to trip both thresholds.
# Run AGAINST A LOCAL DEV INSTANCE ONLY.

set -euo pipefail

TARGET="${1:-http://localhost:3000}"
ATTEMPTS="${2:-10}"

echo "Simulating ${ATTEMPTS} failed logins against ${TARGET}/login ..."

for i in $(seq 1 "${ATTEMPTS}"); do
  # csurf will reject these without a token — that's intentional, the
  # WARN line still ends up in security.log and is what Fail2Ban watches.
  curl -s -o /dev/null -w "Attempt %{http_code}\n" \
       -X POST "${TARGET}/login" \
       -d "username=admin&password=wrong-${i}"
done

echo
echo "Now tail security.log and confirm you see:"
echo "  - multiple 'Failed login' entries"
echo "  - one 'ALERT: brute-force suspected from IP' entry"
echo "  - if Fail2Ban is running with this app's filter installed:"
echo "      sudo fail2ban-client status userhub-auth"
