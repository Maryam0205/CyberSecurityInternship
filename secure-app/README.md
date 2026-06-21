# UserHub Secure — Weeks 4-6 hardening

Hardened User Management System covering the Cybersecurity Interns task
for Weeks 4-6. Built on top of the Week 3 baseline (`week3Tasks/secure-app/`).

## Quick start

```bash
cp .env.example .env
# Generate real secrets:
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(48).toString('hex'))" >> .env
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(48).toString('hex'))" >> .env
# Optionally append a couple of API keys:
node -e "console.log('API_KEYS=' + require('crypto').randomBytes(32).toString('hex'))" >> .env

npm ci
npm start
# → http://localhost:3000
# Seeded admin: admin / Admin#2026Strong
```

### Docker (full stack: WAF + app + Fail2Ban)

```bash
docker compose up --build
# → http://localhost:8080 (entry through ModSecurity WAF)
```

## What's where

| Path | Purpose |
| --- | --- |
| `server.js` | Express bootstrap, helmet/CSP/HSTS, CSRF, sessions, OAuth wiring, rate limits, routes. |
| `middleware/apiKey.js` | Constant-time API-key auth for `/api/*`. |
| `middleware/oauth.js` | Google OAuth 2.0 scaffold via passport. Only enabled when `GOOGLE_CLIENT_ID` is set. |
| `middleware/alert.js` | In-process failed-login counter; emits high-severity log lines at threshold. |
| `middleware/ipBlock.js` | App-layer IP blocklist; reloads `config/blocked-ips.json` every 10s. |
| `routes/api.js` | Machine-to-machine `/api/*` surface (health, users). |
| `logger.js` | winston JSON-line logger → `security.log`. |
| `config/fail2ban/` | Fail2Ban filter + jail.local that watches `security.log`. |
| `config/nginx-waf/` | ModSecurity custom rules layered on top of OWASP CRS. |
| `scripts/` | Brute-force simulator, sqlmap runner, audit runner. |
| `.github/` | Dependabot + security CI workflow. |
| `Dockerfile`, `docker-compose.yml` | Hardened multi-stage build; runs as UID 10001. |

## Task → control map

### Week 4 — Advanced Threat Detection & Web Security

| PDF task | Where |
| --- | --- |
| Fail2Ban / OSSEC real-time monitoring | `config/fail2ban/` + Fail2Ban service in `docker-compose.yml` |
| Alert system for multiple failed login attempts | `middleware/alert.js` — fires `alertType: "brute_force_ip"` / `"credential_stuffing_user"` |
| Rate limiting (express-rate-limit) | `server.js` — `globalLimiter`, `authLimiter`, `apiLimiter` |
| CORS allowlist | `server.js` — `apiCors` mounted on `/api/*` |
| API keys / OAuth | `middleware/apiKey.js` + `middleware/oauth.js` (Google) |
| Content Security Policy | helmet config in `server.js` — per-request nonce |
| HSTS | `strictTransportSecurity` in helmet — 2y preload, prod-only |

### Week 5 — Ethical Hacking & Exploiting Vulnerabilities

| PDF task | Where |
| --- | --- |
| Kali Linux / pentest toolkit | `scripts/run-sqlmap.sh` + procedure in `reports/ethical-hacking-report.tex` |
| SQLMap | `scripts/run-sqlmap.sh` |
| Prevent SQLi with prepared statements | every `db.prepare(...).run(...)` in `server.js` and `routes/api.js` |
| CSRF protection via csurf | `server.js` — `csrfProtection` middleware on all state-changing HTML routes |
| Burp Suite for CSRF testing | procedure in `reports/ethical-hacking-report.tex` §4 |

### Week 6 — Advanced Security Audits & Final Deployment

| PDF task | Where |
| --- | --- |
| OWASP ZAP / Nikto / Lynis | `scripts/run-audits.sh` + raw output under `../reports/raw/` |
| OWASP Top 10 compliance | `../reports/owasp-top10-checklist.tex` |
| Automatic security updates | `.github/dependabot.yml` + `unattended-upgrades` (see `../reports/security-audit-report.tex` §3) |
| Dependency scanning | `.github/workflows/security.yml` — `npm audit`, Trivy |
| Docker security best practices | `Dockerfile` (multi-stage, non-root, alpine), `.dockerignore`, `docker-compose.yml` (read-only FS, no caps, no-new-privs) |
| Penetration test | `../reports/pentest-report.tex` |

### Bonus

| PDF task | Where |
| --- | --- |
| Zero Trust principles | `../docs/zero-trust.md` |
| Web Application Firewall | nginx + ModSecurity service in `docker-compose.yml`, custom rules in `config/nginx-waf/` |
| Social engineering simulation | `../docs/phishing-simulation.md` |

## Verify the controls

```bash
# 1. Watch the log while you simulate brute force
npm start
# new terminal:
tail -f security.log &
./scripts/simulate-brute-force.sh

# 2. Confirm CSP nonce rotates per request
curl -is http://localhost:3000/login | grep -i content-security-policy
curl -is http://localhost:3000/login | grep -i content-security-policy   # different nonce

# 3. Reject /api/* without an API key
curl -is http://localhost:3000/api/users

# 4. CSRF token enforced on POST
curl -is -X POST http://localhost:3000/login -d 'username=x&password=y'
# → 403 Invalid CSRF token

# 5. Verify rate limit
for i in $(seq 1 25); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/login; done
# → last responses are 429

# 6. Run the full audit suite (Linux/WSL with docker)
./scripts/run-audits.sh
```

## Notes on choices

- **csurf is deprecated.** The PDF specifies it by name, so the code uses
  `csurf`. The modern equivalent is `csrf-csrf`; swap is mechanical when
  the assignment is graded.
- **API keys + OAuth.** API keys cover machine-to-machine on `/api/*`.
  OAuth (Google) covers user sign-in. Both options from the PDF are
  satisfied without forcing one onto the wrong surface.
- **Local SQLite.** `:memory:` keeps the demo simple and matches week 3.
  Production would point at a real database — the prepared-statement
  pattern is unchanged.

## See also

- [Cybersecurity Interns Task PDF](../Cyber%20Security%20Interns%20Task.pdf)
- [TASKS.md](../TASKS.md) — checklist of every deliverable.
- `../reports/` — ethical hacking, security audit, pentest reports.
- `../docs/` — zero trust, phishing simulation, video script.
