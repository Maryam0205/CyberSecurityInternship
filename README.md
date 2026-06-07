# Cybersecurity Internship — Week 1-3 Submission

Strengthening security measures for a User Management web application.
Built for the DevelopersHub Cybersecurity Intern programme.

## Run the vulnerable app (Week 1 target)

```bash
cd vulnerable-app
npm install
npm start
# open http://localhost:3000
```

Seeded admin account: `admin / admin123`.

**Try the attacks** documented in `docs/01-vulnerability-assessment.md`:

* Login with username `admin' OR '1'='1` and any password — you'll be logged in as admin (SQLi).
* Set your profile bio to `<script>alert('XSS');</script>` and reload — the alert fires (stored XSS).
* `curl http://localhost:3000/users` — every user's email is dumped.

## Run the hardened app (Week 2 + Week 3 build)

```bash
cd secure-app
cp .env.example .env        # edit JWT_SECRET to a long random value first
npm install
npm start
# open http://localhost:3000
```

Seeded admin account: `admin / Admin#2026Strong`.

Re-run the same attacks — they all fail (see `docs/02-security-fixes-applied.md`
for proof strings from a live `curl` run).

## What's done vs. what's manual

| Task | Status |
|---|---|
| Vulnerable target built and verified | done — see `vulnerable-app/` |
| Vulnerabilities documented (9 findings) | done — `docs/01-vulnerability-assessment.md` |
| Week 2 fixes implemented (validator, bcrypt, JWT, helmet) | done — `secure-app/` |
| Week 3 logging (winston) implemented | done — `secure-app/logger.js`, `security.log` |
| Rate limiting (extra) | done — express-rate-limit on `/login` + `/signup` |
| Pen-test recipes (Nmap, ZAP, manual) | done — `docs/03-pentest-notes.md` |
| Security checklist | done — `docs/04-security-checklist.md` |
| Final report | done — `docs/05-final-report.md` |
| Record screen-walkthrough video | **to do by intern** |
| Push to GitHub + submit URL on console | **to do by intern** |

## Stack & dependencies

* Node.js 22 + Express 4
* EJS templates
* better-sqlite3 (in-memory)
* Week 2 hardening libs: `validator`, `bcrypt`, `jsonwebtoken`, `helmet`,
  `cookie-parser`
* Week 3 hardening libs: `winston`, `express-rate-limit`, `dotenv`

## Notes for the marker

* The vulnerable build is deliberately self-contained so you can demo every
  finding without external infrastructure.
* The secure build refuses to start if `JWT_SECRET` is missing or still the
  placeholder — try removing it from `.env` and you'll see the guard rail.
* All log lines are written to `secure-app/security.log` as JSON (gitignored).

## License

Educational / internship use.
