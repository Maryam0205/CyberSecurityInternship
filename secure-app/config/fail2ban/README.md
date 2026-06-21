# Fail2Ban setup — UserHub Secure (Week 4 Task 1)

Fail2Ban is a log-watching daemon. Point it at the app's `security.log`, give
it a regex that matches failed logins, and it drops the offending IP at the
host firewall (`iptables` / `nftables`).

## Why Fail2Ban (vs. just in-app rate limiting)

The app already rate-limits auth endpoints to 20/15min/IP, and the alert
middleware fires a high-severity log line at 5 failures from one IP. Those
controls live inside Node. Fail2Ban moves the response one layer down — to
the kernel — so banned IPs cannot even open a TCP connection. That:

- protects all ports on the host, not just `/login`;
- survives an application restart (bans persist via `iptables` rules);
- has zero per-request CPU cost once the rule is in place.

OSSEC is the heavier alternative — full HIDS with file-integrity monitoring
on top of log analysis. Fail2Ban is sufficient for the brute-force scope of
this task.

## Files in this directory

| File | Where it goes on a Linux host |
| --- | --- |
| `filter.d/userhub-auth.conf` | `/etc/fail2ban/filter.d/userhub-auth.conf` |
| `jail.local`                 | `/etc/fail2ban/jail.d/userhub-auth.local` |

The filter matches three event types in `security.log`:

1. `"message":"Failed login"` — every individual failed credential check.
2. `"message":"ALERT: brute-force suspected from IP"` — the in-app alert
   middleware fires this after `THRESHOLD_PER_IP` failures inside the
   sliding window (see [middleware/alert.js](../../middleware/alert.js)).
3. `"message":"API request rejected: invalid API key"` — repeated bad API
   keys are an enumeration signal worth banning on.

## Install (Debian / Ubuntu)

```bash
sudo apt update && sudo apt install -y fail2ban
sudo cp filter.d/userhub-auth.conf /etc/fail2ban/filter.d/userhub-auth.conf
sudo cp jail.local /etc/fail2ban/jail.d/userhub-auth.local

# Tell the app to write its log where the jail expects it (or symlink):
sudo mkdir -p /var/log/userhub
sudo ln -s /opt/userhub/security.log /var/log/userhub/security.log

sudo systemctl enable --now fail2ban
sudo systemctl reload fail2ban
```

## Verify

```bash
# Show jail status (number of currently banned IPs, total found, etc.)
sudo fail2ban-client status userhub-auth

# Test the regex against the live log
sudo fail2ban-regex /var/log/userhub/security.log \
                    /etc/fail2ban/filter.d/userhub-auth.conf

# Manually unban an IP if you ban yourself
sudo fail2ban-client set userhub-auth unbanip 203.0.113.5
```

## Alerts

`jail.local` sets `action = %(action_mwl)s` — Fail2Ban runs `iptables` AND
sends an email with the offender's whois data on every ban. For Slack /
PagerDuty integration, replace with a custom action under
`/etc/fail2ban/action.d/` that POSTs to a webhook.

The in-app alert engine (`middleware/alert.js`) is the second half of the
"alert system for multiple failed login attempts" deliverable — it writes a
distinct high-severity log line at threshold so SIEMs / log shippers can
trigger on `"alertType":"brute_force_ip"` without parsing every failed
login.

## OSSEC alternative

If you'd prefer OSSEC over Fail2Ban, the equivalent setup is:

1. Install `ossec-hids-server` on the host.
2. Add a custom decoder to `/var/ossec/etc/local_decoder.xml` that pulls the
   JSON message + IP fields out of `security.log`.
3. Add a rule under `/var/ossec/rules/local_rules.xml` that fires on the
   "Failed login" or "ALERT" messages with frequency=5/timeframe=600.
4. Use OSSEC's active-response feature with `firewall-drop` as the command.

Fail2Ban is recommended here because it's lighter, simpler, and the task
explicitly lists it as a valid choice.
