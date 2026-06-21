// API key authentication for /api/* surface.
// Keys are loaded from API_KEYS env (comma-separated). Comparison is
// constant-time so attackers can't time-leak prefixes.

const crypto = require('crypto');
const logger = require('../logger');

function loadKeys() {
  return (process.env.API_KEYS || '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean);
}

const VALID_KEYS = loadKeys();

function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function requireApiKey(req, res, next) {
  const presented = req.get('x-api-key') || '';
  if (!presented) {
    logger.warn('API request rejected: missing X-API-Key', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Missing X-API-Key header' });
  }
  const ok = VALID_KEYS.some((k) => timingSafeEqual(presented, k));
  if (!ok) {
    logger.warn('API request rejected: invalid API key', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
}

module.exports = { requireApiKey };
