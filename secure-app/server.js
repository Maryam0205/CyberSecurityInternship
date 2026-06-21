// ============================================================================
// SECURE User Management System — Weeks 4-6 hardening on top of week3 baseline.
//
// Each new control is tagged with a `W4.*`, `W5.*`, or `W6.*` marker and a
// short note linking back to the PDF task. See README.md for the full map.
// ============================================================================

require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const csrf = require('csurf');                 // W5.3: CSRF middleware
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const Database = require('better-sqlite3');

const logger = require('./logger');
const { blockIp } = require('./middleware/ipBlock');
const { recordFailedLogin, recordSuccessfulLogin } = require('./middleware/alert');
const { configureOAuth, passport } = require('./middleware/oauth');
const buildApiRouter = require('./routes/api');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const IS_PROD = process.env.NODE_ENV === 'production';
const BCRYPT_COST = 12;

if (!JWT_SECRET || JWT_SECRET === 'replace-me-with-a-long-random-secret') {
  logger.error('JWT_SECRET is missing or still the default. Set it in .env before starting.');
  process.exit(1);
}

// W4: when running behind a reverse proxy (nginx/WAF/Docker), trust X-Forwarded-*
// so req.ip reflects the real client (so rate-limiter/Fail2Ban work correctly).
// Off by default — only enable when you actually have a trusted proxy in front.
if (process.env.TRUST_PROXY) {
  app.set('trust proxy', process.env.TRUST_PROXY);
}

// ----- Database --------------------------------------------------------------

const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    bio TEXT DEFAULT ''
  );
`);
const seedHash = bcrypt.hashSync('Admin#2026Strong', BCRYPT_COST);
db.prepare(
  'INSERT INTO users (username, email, password, bio) VALUES (?, ?, ?, ?)'
).run('admin', 'admin@example.com', seedHash, 'I am the administrator.');

// ----- Headers (Helmet) ------------------------------------------------------

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

// W4.3: per-request CSP nonce. Inline <script> in templates use
// `nonce="<%= cspNonce %>"`. Without the nonce, an injected <script> from a
// reflected XSS payload is blocked by the browser.
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use(
  helmet({
    // W4.3: CSP — explicit allowlist; nonce-based scripts; no inline/eval.
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
        styleSrc: ["'self'", "'unsafe-inline'"], // EJS templates use plain <style>
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'", 'https://accounts.google.com'],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: IS_PROD ? [] : null,
      },
    },
    // W4.3: HSTS — 2 years + preload + subdomains. Only emitted in prod (so
    // local dev over plain HTTP doesn't pin localhost to HTTPS).
    strictTransportSecurity: IS_PROD
      ? { maxAge: 63072000, includeSubDomains: true, preload: true }
      : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false, // EJS pages don't need COEP isolation
    crossOriginResourcePolicy: { policy: 'same-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
  })
);

// ----- IP blocklist (defence in depth alongside Fail2Ban) --------------------

app.use(blockIp);

// ----- CORS (only on /api/*) -------------------------------------------------

// W4.2: explicit allowlist; no wildcards with credentials; OPTIONS preflight
// is handled by the same middleware. Browser-side flows (the EJS pages) are
// same-origin so they don't go through this — only /api/* needs it.
const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const apiCors = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);              // curl / same-origin
    if (allowedOrigins.includes(origin)) return cb(null, true);
    logger.warn('CORS rejected origin', { origin });
    cb(new Error('Origin not allowed by CORS policy'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key'],
  credentials: false,
  maxAge: 600,
});

// ----- Body parsers, static, sessions ---------------------------------------

app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session is only used for OAuth handshake state (passport needs req.session).
// JWT remains the source of truth for normal auth — see issueToken().
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',          // 'lax' needed so OAuth redirect can carry the cookie
      secure: IS_PROD,
      maxAge: 10 * 60 * 1000,
    },
  })
);

const oauthState = configureOAuth(db, BCRYPT_COST, bcrypt);
app.use(passport.initialize());
app.use(passport.session());

// ----- Rate limiting ---------------------------------------------------------

// W4.2: global limiter — protects everything from volumetric abuse.
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests. Slow down.',
});
app.use(globalLimiter);

// W4.2: tight limiter on auth endpoints to slow brute force / credential stuffing.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many auth attempts. Try again in 15 minutes.',
});

// W4.2: stricter limiter on /api/* for machine clients.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.get('x-api-key') || req.ip,
  message: { error: 'Rate limit exceeded' },
});

// ----- CSRF (W5.3) -----------------------------------------------------------

// csurf is deprecated by Express but the PDF specifies it; the equivalent
// modern choice is `csrf-csrf`. The protection model here is "double-submit
// cookie" using a csrf-token cookie + form-field token. Applied only to the
// HTML form surface, not to /api/* (API uses X-API-Key, not cookies, so it's
// not vulnerable to CSRF).
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: IS_PROD,
  },
});

// ----- API router (CORS + API key + rate limit) ------------------------------

app.use('/api', apiCors, apiLimiter, buildApiRouter(db));

// ----- Auth helpers ----------------------------------------------------------

function issueToken(res, user) {
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: '1h',
  });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: IS_PROD,
    maxAge: 60 * 60 * 1000,
  });
}

function currentUser(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return db.prepare('SELECT id, username, email, bio FROM users WHERE id = ?').get(payload.id);
  } catch (e) {
    logger.warn('Rejected invalid/expired token', { error: e.message });
    return null;
  }
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  req.user = user;
  next();
}

// ----- HTML routes -----------------------------------------------------------

app.get('/', (req, res) => {
  res.render('home', { user: currentUser(req), oauthEnabled: oauthState.enabled });
});

app.get('/signup', csrfProtection, (req, res) => {
  res.render('signup', { error: null, values: {}, csrfToken: req.csrfToken() });
});

app.post('/signup', authLimiter, csrfProtection, async (req, res) => {
  const username = (req.body.username || '').trim();
  const email = (req.body.email || '').trim();
  const password = req.body.password || '';

  const errors = [];
  if (!validator.isAlphanumeric(username) || username.length < 3 || username.length > 32) {
    errors.push('Username must be 3-32 alphanumeric characters.');
  }
  if (!validator.isEmail(email)) errors.push('Invalid email address.');
  if (
    !validator.isStrongPassword(password, {
      minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1,
    })
  ) {
    errors.push('Password must be 8+ chars with upper, lower, number, and symbol.');
  }

  if (errors.length) {
    return res.render('signup', {
      error: errors.join(' '),
      values: { username, email },
      csrfToken: req.csrfToken(),
    });
  }

  try {
    const hash = await bcrypt.hash(password, BCRYPT_COST);
    const result = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run(username, validator.normalizeEmail(email), hash);
    logger.info('User signed up', { userId: result.lastInsertRowid, username });
    issueToken(res, { id: result.lastInsertRowid, username });
    res.redirect('/profile');
  } catch (e) {
    logger.warn('Signup failed', { username, error: e.message });
    res.render('signup', {
      error: 'Could not create account.',
      values: { username, email },
      csrfToken: req.csrfToken(),
    });
  }
});

app.get('/login', csrfProtection, (req, res) => {
  res.render('login', {
    error: null,
    csrfToken: req.csrfToken(),
    oauthEnabled: oauthState.enabled,
  });
});

app.post('/login', authLimiter, csrfProtection, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  const dummyHash = '$2b$12$abcdefghijklmnopqrstuv.invalidplaceholderhashforuserenum';
  const ok = await bcrypt.compare(password, user ? user.password : dummyHash);

  if (!user || !ok) {
    recordFailedLogin({ ip: req.ip, username });        // W4.1: feed alert engine
    logger.warn('Failed login', { username, ip: req.ip });
    return res.render('login', {
      error: 'Invalid credentials',
      csrfToken: req.csrfToken(),
      oauthEnabled: oauthState.enabled,
    });
  }

  recordSuccessfulLogin({ username });
  logger.info('User logged in', { userId: user.id, username: user.username });
  issueToken(res, user);
  res.redirect('/profile');
});

// ----- OAuth routes (only registered when configured) ------------------------

if (oauthState.enabled) {
  app.get(
    '/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
  );
  app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
      issueToken(res, req.user);
      res.redirect('/profile');
    }
  );
}

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  req.session.destroy(() => res.redirect('/'));
});

app.get('/profile', requireLogin, csrfProtection, (req, res) => {
  res.render('profile', { user: req.user, csrfToken: req.csrfToken() });
});

app.post('/profile', requireLogin, csrfProtection, (req, res) => {
  const bio = (req.body.bio || '').slice(0, 1000);
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.user.id);
  logger.info('Profile updated', { userId: req.user.id });
  res.redirect('/profile');
});

app.get('/users', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT username FROM users ORDER BY username').all();
  res.json(rows);
});

// ----- Error handler ---------------------------------------------------------

app.use((err, req, res, next) => {
  // csurf raises EBADCSRFTOKEN on missing/invalid token — return 403 clearly.
  if (err.code === 'EBADCSRFTOKEN') {
    logger.warn('CSRF token rejected', { ip: req.ip, path: req.path });
    return res.status(403).send('Invalid CSRF token. Refresh and try again.');
  }
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  res.status(500).send(IS_PROD ? 'Internal Server Error' : err.stack);
});

app.listen(PORT, () => {
  logger.info('Application started', {
    port: PORT,
    env: process.env.NODE_ENV || 'development',
    oauth: oauthState.enabled,
    corsAllowedOrigins: allowedOrigins,
  });
  console.log(`Secure app running at http://localhost:${PORT}`);
  console.log('Seeded admin -> username: admin, password: Admin#2026Strong');
});
