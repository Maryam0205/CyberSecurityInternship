// Machine-to-machine /api/* surface, guarded by API key auth.
// This is intentionally a small read-only surface — anything sensitive should
// stay on the user-cookie-authenticated routes.

const express = require('express');
const { requireApiKey } = require('../middleware/apiKey');

module.exports = function buildApiRouter(db) {
  const router = express.Router();

  // CORS pre-flight + main response are added by the global cors() middleware
  // in server.js; we just enforce auth here.
  router.use(requireApiKey);

  router.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
  });

  router.get('/users', (req, res) => {
    // Public-safe fields only — never expose email/password/bio to API callers.
    const rows = db.prepare('SELECT id, username FROM users ORDER BY username').all();
    res.json({ users: rows });
  });

  router.get('/users/:id', (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ user });
  });

  return router;
};
