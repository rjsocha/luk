# luk_status - check_mk local check for lukd

Install: `/usr/lib/check_mk_agent/local/luk_status` (executable, Python 3 stdlib only).

Input: `/var/lib/luk/status/process/status.json` (env `LUK_STATUS`), written by the process role.
Thresholds: `/etc/site/luk/check.conf` (env `LUK_CHECK_CONF`), see `check.conf.example`.
A missing check.conf means no expectations. `LUK_CHECK_NOW` (RFC 3339) fixes the clock (tests).

One service `luk <pipeline> <sender>` per pipeline entry of status.json, plus one per
expectation section that matches no entry. One service
`luk watch <storage> <pipeline> <origin>/<file>` per watched series of a storage (`-` for
an empty pipeline) and `luk watch <storage> rule <n>` per watch rule no series matches.
Spaces and non-printable characters in names become `_`.

Rules:
- `failed` > 0: CRIT, with the last error (sanitized, 200 chars) and `lukd queue ls / rm`
  (the failure records; a failed upload is deleted and has to be sent again).
- With an expectation (first matching section wins): no success ever or older than `crit_age`
  is CRIT, older than `warn_age` is WARN, last size below `min_size` is WARN.
- Expectation with no entry: CRIT "never received".
- No expectation: OK, last success age shown for information.
- Watch services: the state and message lukd wrote (the thresholds are the `watch` rules
  of the storage in the lukd configuration, not check.conf); metrics `age` (of the newest
  copy) and `size`. An evaluation older than 10 minutes is UNKNOWN ("is lukd process
  running?"): the process role evaluates every minute.
- A status.json of an older lukd (an array of pipeline entries) is read too.
- status.json missing, unreadable or invalid: one service `luk status` UNKNOWN.
  Malformed check.conf: UNKNOWN "check.conf: ...".

Tests: `python3 -m unittest discover -s contrib/checkmk`
