# luk_status - check_mk local check for lukd

Install: `/usr/lib/check_mk_agent/local/luk_status` (executable, Python 3 stdlib only).

Input: `/var/lib/luk/status.json` (env `LUK_STATUS`).
Thresholds: `/etc/site/luk/check.conf` (env `LUK_CHECK_CONF`), see `check.conf.example`.
A missing check.conf means no expectations. `LUK_CHECK_NOW` (RFC 3339) fixes the clock (tests).

One service `luk <pipeline> <sender>` per status.json entry, plus one per expectation
section that matches no entry. Spaces and non-printable characters in names become `_`.

Rules:
- `failed` > 0: CRIT, with the last error (sanitized, 200 chars) and `lukd queue ls / rm / retry`.
- With an expectation (first matching section wins): no success ever or older than `crit_age`
  is CRIT, older than `warn_age` is WARN, last size below `min_size` is WARN.
- Expectation with no entry: CRIT "never received".
- No expectation: OK, last success age shown for information.
- status.json missing, unreadable or invalid: one service `luk status` UNKNOWN.
  Malformed check.conf: UNKNOWN "check.conf: ...".

Tests: `python3 -m unittest discover -s contrib/checkmk`
