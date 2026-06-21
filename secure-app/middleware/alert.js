// In-process failed-login counter that emits a high-severity alert log line
// when a single IP or username crosses the threshold inside a short window.
// security.log is the canonical audit trail; Fail2Ban watches the same file
// and applies a firewall-level ban (see config/fail2ban/).

const logger = require('../logger');

const WINDOW_MS = 10 * 60 * 1000;        // 10 minute sliding window
const THRESHOLD_PER_IP = 5;              // alert after 5 failures from one IP
const THRESHOLD_PER_USER = 3;            // alert after 3 failures for one user

const ipFailures = new Map();            // ip -> [timestamps]
const userFailures = new Map();          // username -> [timestamps]

function prune(arr, now) {
  while (arr.length && now - arr[0] > WINDOW_MS) arr.shift();
}

function recordFailedLogin({ ip, username }) {
  const now = Date.now();

  const ipArr = ipFailures.get(ip) || [];
  ipArr.push(now);
  prune(ipArr, now);
  ipFailures.set(ip, ipArr);

  const userArr = userFailures.get(username) || [];
  userArr.push(now);
  prune(userArr, now);
  userFailures.set(username, userArr);

  if (ipArr.length >= THRESHOLD_PER_IP) {
    // 'error' level so Fail2Ban / log shippers can match severity.
    logger.error('ALERT: brute-force suspected from IP', {
      ip,
      failuresInWindow: ipArr.length,
      windowMinutes: WINDOW_MS / 60_000,
      alertType: 'brute_force_ip',
    });
  }
  if (userArr.length >= THRESHOLD_PER_USER) {
    logger.error('ALERT: repeated failed logins for user', {
      username,
      failuresInWindow: userArr.length,
      windowMinutes: WINDOW_MS / 60_000,
      alertType: 'credential_stuffing_user',
    });
  }
}

function recordSuccessfulLogin({ username }) {
  // Reset the per-user counter on success so legitimate corrections don't
  // accumulate forever.
  userFailures.delete(username);
}

module.exports = { recordFailedLogin, recordSuccessfulLogin };
