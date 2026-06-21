// Lightweight in-process IP block list, fed by Fail2Ban (or any external
// monitoring) via a JSON file at config/blocked-ips.json. The file is
// re-read on a short interval so bans take effect without restarting Node.
// Real production deployments should drop bans at the firewall (iptables /
// nftables / Cloud WAF) — this is an application-layer defence in depth.

const fs = require('fs');
const path = require('path');
const logger = require('../logger');

const BLOCKLIST_PATH = path.join(__dirname, '..', 'config', 'blocked-ips.json');
let blocked = new Set();
let lastMtime = 0;

function reload() {
  try {
    const stat = fs.statSync(BLOCKLIST_PATH);
    if (stat.mtimeMs === lastMtime) return;
    lastMtime = stat.mtimeMs;
    const data = JSON.parse(fs.readFileSync(BLOCKLIST_PATH, 'utf8'));
    blocked = new Set(Array.isArray(data) ? data : data.blocked || []);
    logger.info('Reloaded IP blocklist', { count: blocked.size });
  } catch (e) {
    if (e.code !== 'ENOENT') logger.warn('Blocklist reload failed', { error: e.message });
  }
}

reload();
setInterval(reload, 10_000).unref();

function blockIp(req, res, next) {
  if (blocked.has(req.ip)) {
    logger.warn('Blocked IP rejected', { ip: req.ip, path: req.path });
    return res.status(403).send('Forbidden');
  }
  next();
}

module.exports = { blockIp };
