// ============================================================================
// VULNERABLE User Management System — DO NOT USE IN PRODUCTION.
// This is the Week 1 "target" application. It is intentionally insecure so we
// can demonstrate SQL injection, XSS, weak password storage, and missing
// security headers during the vulnerability assessment.
// ============================================================================

const express = require('express');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = 3000;

// In-memory SQLite — fresh on every restart, good enough for the demo.
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,   -- VULN: plaintext password storage
    bio TEXT DEFAULT ''
  );
`);

// Seed an admin account so the SQLi demo lands on something interesting.
db.prepare(
  "INSERT INTO users (username, email, password, bio) VALUES (?, ?, ?, ?)"
).run('admin', 'admin@example.com', 'admin123', 'I am the administrator.');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// VULN: no helmet, no CSP, no HSTS, no X-Frame-Options — default Express headers only.

// Tiny "auth" middleware that trusts a plain cookie. (VULN: no signing, no JWT.)
function currentUser(req) {
  const uid = req.cookies.uid;
  if (!uid) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
}

app.get('/', (req, res) => {
  const user = currentUser(req);
  res.render('home', { user });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signup', (req, res) => {
  const { username, email, password } = req.body;

  // VULN: no input validation at all.
  // VULN: password stored as plaintext.
  try {
    const result = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run(username, email, password);
    res.cookie('uid', result.lastInsertRowid);
    res.redirect('/profile');
  } catch (e) {
    res.render('signup', { error: e.message });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULN: classic SQL injection — string-concatenated query.
  // Try logging in with username = `admin' OR '1'='1` and any password.
  const sql =
    "SELECT * FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  let user;
  try {
    user = db.prepare(sql).get();
  } catch (e) {
    return res.render('login', { error: 'SQL error: ' + e.message });
  }

  if (!user) {
    return res.render('login', { error: 'Invalid credentials' });
  }
  res.cookie('uid', user.id); // VULN: not httpOnly, not signed, not secure.
  res.redirect('/profile');
});

app.get('/logout', (req, res) => {
  res.clearCookie('uid');
  res.redirect('/');
});

app.get('/profile', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  res.render('profile', { user });
});

app.post('/profile', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  // VULN: bio rendered with <%- %> (raw), so any <script> here fires on view.
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(req.body.bio, user.id);
  res.redirect('/profile');
});

// Public "search" — leaks every user's email/bio. VULN: information disclosure.
app.get('/users', (req, res) => {
  const rows = db.prepare('SELECT id, username, email, bio FROM users').all();
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`Vulnerable app running at http://localhost:${PORT}`);
  console.log('Seeded admin account -> username: admin, password: admin123');
});
