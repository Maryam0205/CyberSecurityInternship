// ============================================================================
// SECURE User Management System
// Hardened version of vulnerable-app/, with all Week 2 & Week 3 fixes applied.
// Each fix is tagged with `FIX:` and a brief note pointing back to the vuln.
// ============================================================================

require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const Database = require('better-sqlite3');
const path = require('path');

const logger = require('./logger');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const IS_PROD = process.env.NODE_ENV === 'production';
const BCRYPT_COST = 12;

if (!JWT_SECRET || JWT_SECRET === 'replace-me-with-a-long-random-secret') {
  // Fail loud rather than booting with a guessable secret.
  logger.error('JWT_SECRET is missing or still the default. Set it in .env before starting.');
  process.exit(1);
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

// Seed an admin with a properly hashed password.
const seedHash = bcrypt.hashSync('Admin#2026Strong', BCRYPT_COST);
db.prepare(
  'INSERT INTO users (username, email, password, bio) VALUES (?, ?, ?, ?)'
).run('admin', 'admin@example.com', seedHash, 'I am the administrator.');

// ----- Middleware ------------------------------------------------------------

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by'); // FIX: stop leaking the framework.

// FIX (Week 2.3): helmet sets a sensible bundle of security headers
// (CSP, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, etc.).
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"], // FIX: blocks inline <script> from XSS payloads.
        styleSrc: ["'self'", "'unsafe-inline'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
      },
    },
  })
);

app.use(express.urlencoded({ extended: true, limit: '10kb' })); // FIX: cap body size.
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// FIX: rate-limit auth endpoints to slow brute force / credential stuffing.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many attempts. Try again in 15 minutes.',
});

// ----- Auth helpers ----------------------------------------------------------

function issueToken(res, user) {
  // FIX (Week 2.2): JWT instead of trusting a plain cookie.
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: '1h',
  });
  res.cookie('token', token, {
    httpOnly: true,           // FIX: JS can't read the cookie -> XSS can't steal it.
    sameSite: 'strict',       // FIX: blocks CSRF on cookie auth.
    secure: IS_PROD,          // FIX: only sent over HTTPS in production.
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

// ----- Routes ----------------------------------------------------------------

app.get('/', (req, res) => {
  res.render('home', { user: currentUser(req) });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null, values: {} });
});

app.post('/signup', authLimiter, async (req, res) => {
  const username = (req.body.username || '').trim();
  const email = (req.body.email || '').trim();
  const password = req.body.password || '';

  // FIX (Week 2.1): validate every input at the trust boundary.
  const errors = [];
  if (!validator.isAlphanumeric(username) || username.length < 3 || username.length > 32) {
    errors.push('Username must be 3-32 alphanumeric characters.');
  }
  if (!validator.isEmail(email)) {
    errors.push('Invalid email address.');
  }
  if (
    !validator.isStrongPassword(password, {
      minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1,
    })
  ) {
    errors.push('Password must be 8+ chars with upper, lower, number, and symbol.');
  }

  if (errors.length) {
    return res.render('signup', { error: errors.join(' '), values: { username, email } });
  }

  try {
    // FIX (Week 2.1): bcrypt hash + salt instead of plaintext storage.
    const hash = await bcrypt.hash(password, BCRYPT_COST);
    // FIX: parameterised query -> SQL injection impossible.
    const result = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run(username, validator.normalizeEmail(email), hash);

    logger.info('User signed up', { userId: result.lastInsertRowid, username });
    issueToken(res, { id: result.lastInsertRowid, username });
    res.redirect('/profile');
  } catch (e) {
    logger.warn('Signup failed', { username, error: e.message });
    // Don't reveal whether it was a duplicate username vs other error.
    res.render('signup', { error: 'Could not create account.', values: { username, email } });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', authLimiter, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  // FIX: parameterised query -> SQL injection impossible.
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  // Constant-ish-time check: still run bcrypt.compare even on unknown user
  // so timing doesn't reveal whether the username existed.
  const dummyHash = '$2b$12$abcdefghijklmnopqrstuv.invalidplaceholderhashforuserenum';
  const hashToCheck = user ? user.password : dummyHash;
  const ok = await bcrypt.compare(password, hashToCheck);

  if (!user || !ok) {
    logger.warn('Failed login', { username, ip: req.ip });
    return res.render('login', { error: 'Invalid credentials' });
  }

  logger.info('User logged in', { userId: user.id, username: user.username });
  issueToken(res, user);
  res.redirect('/profile');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.get('/profile', requireLogin, (req, res) => {
  res.render('profile', { user: req.user });
});

app.post('/profile', requireLogin, (req, res) => {
  // FIX: cap bio length and store only a sanitised string. We escape on render
  // (the EJS `<%= %>` tag), so DB content stays as the user typed it but
  // can never break out of HTML context.
  const bio = (req.body.bio || '').slice(0, 1000);
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.user.id);
  logger.info('Profile updated', { userId: req.user.id });
  res.redirect('/profile');
});

// FIX: the old `/users` endpoint dumped every email — gone.
// Authenticated users can see a directory of usernames only.
app.get('/users', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT username FROM users ORDER BY username').all();
  res.json(rows);
});

// FIX: don't leak stack traces in production.
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  res.status(500).send(IS_PROD ? 'Internal Server Error' : err.stack);
});

app.listen(PORT, () => {
  logger.info('Application started', { port: PORT, env: process.env.NODE_ENV || 'development' });
  console.log(`Secure app running at http://localhost:${PORT}`);
  console.log('Seeded admin -> username: admin, password: Admin#2026Strong');
});
