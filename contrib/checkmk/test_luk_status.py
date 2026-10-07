import importlib.machinery
import importlib.util
import json
import os
import re
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("luk_status", os.path.join(HERE, "luk_status"))
_spec = importlib.util.spec_from_loader("luk_status", _loader)
ls = importlib.util.module_from_spec(_spec)
_loader.exec_module(ls)

NOW = "2026-09-30T12:00:00Z"
CONF = """
[defaults]
warn_age = 26h
crit_age = 50h

[devdb replica.*.example.net]   # inline comment
min_size = 300M
"""


def entry(**kw):
    e = {"pipeline": "devdb", "sender": "replica.aws.example.net", "tags": [],
         "last_id": "x", "last_received": "2026-09-30T06:00:00Z",
         "last_success": "2026-09-30T06:00:00Z", "last_failure": "",
         "failed_step": "", "error": "", "size": 400 * 1024**2, "failed": 0}
    e.update(kw)
    return e


class Base(unittest.TestCase):
    def check(self, entries, conf=CONF, raw=None):
        with tempfile.TemporaryDirectory() as d:
            env = {"LUK_CHECK_NOW": NOW, "LUK_STATUS": os.path.join(d, "status.json"),
                   "LUK_CHECK_CONF": os.path.join(d, "check.conf")}
            if entries is not None or raw is not None:
                with open(env["LUK_STATUS"], "w") as f:
                    f.write(raw if raw is not None else json.dumps(entries))
            if conf is not None:
                with open(env["LUK_CHECK_CONF"], "w") as f:
                    f.write(conf)
            return ls.run(env)

    def one(self, entries, **kw):
        out = self.check(entries, **kw)
        self.assertEqual(len(out), 1, out)
        return out[0]


class TestPaths(unittest.TestCase):
    def test_default_status(self):
        # Written by the process role under the lukd root.
        self.assertEqual(ls.DEFAULT_STATUS, "/var/lib/luk/data/status/process/status.json")


class TestParsing(unittest.TestCase):
    def test_duration(self):
        self.assertEqual(ls.parse_duration("30s"), 30)
        self.assertEqual(ls.parse_duration("5m"), 300)
        self.assertEqual(ls.parse_duration("26h"), 93600)
        self.assertEqual(ls.parse_duration("2D"), 172800)
        for bad in ("", "h", "1w", "1.5h", "-1h", "10"):
            with self.assertRaises(ValueError):
                ls.parse_duration(bad)

    def test_size(self):
        self.assertEqual(ls.parse_size("100"), 100)
        self.assertEqual(ls.parse_size("1k"), 1024)
        self.assertEqual(ls.parse_size("300M"), 300 * 1024**2)
        self.assertEqual(ls.parse_size("2g"), 2 * 1024**3)
        self.assertEqual(ls.parse_size("1T"), 1024**4)
        for bad in ("", "M", "1X", "1.5G", "-1M"):
            with self.assertRaises(ValueError):
                ls.parse_size(bad)

    def test_names(self):
        self.assertEqual(ls.clean_name("a b\tc\nd"), "a_b_c_d")
        self.assertEqual(ls.clean_name("h:1"), "h:1")
        self.assertEqual(ls.clean_name('a"b\x00'), "a_b_")
        self.assertEqual(ls.clean_name(""), "_")

    def test_time(self):
        self.assertIsNone(ls.parse_time(""))
        self.assertIsNone(ls.parse_time(None))
        self.assertEqual(ls.parse_time("2026-09-30T12:00:00Z"), ls.parse_time("2026-09-30T14:00:00+02:00"))
        with self.assertRaises(ValueError):
            ls.parse_time("yesterday")


class TestRules(Base):
    def test_ok(self):
        l = self.one([entry()])
        self.assertTrue(l.startswith('0 "luk devdb replica.aws.example.net" age=21600;93600;180000|size=419430400;314572800|failed=0;;1 '), l)
        self.assertIn("last success 6h 0m ago", l)

    def test_warn_age(self):
        l = self.one([entry(last_success="2026-09-29T00:00:00Z")])
        self.assertTrue(l.startswith("1 "), l)
        self.assertIn("warn_age", l)

    def test_crit_age(self):
        l = self.one([entry(last_success="2026-09-27T00:00:00Z")])
        self.assertTrue(l.startswith("2 "), l)
        self.assertIn("crit_age", l)

    def test_boundary_not_older(self):
        l = self.one([entry(last_success="2026-09-29T10:00:00Z")])  # exactly 26h
        self.assertTrue(l.startswith("0 "), l)

    def test_never_succeeded(self):
        for v in ("", None):
            l = self.one([entry(last_success=v)])
            self.assertTrue(l.startswith("2 "), l)
            self.assertIn("never succeeded", l)
            self.assertNotIn("age=", l)

    def test_min_size(self):
        l = self.one([entry(size=100)])
        self.assertTrue(l.startswith("1 "), l)
        self.assertIn("min_size", l)

    def test_crit_beats_size_warn(self):
        l = self.one([entry(size=1, last_success="2026-09-20T00:00:00Z")])
        self.assertTrue(l.startswith("2 "), l)

    def test_failed(self):
        l = self.one([entry(failed=2, error="boom\nbad|pipe" + "x" * 300)])
        self.assertTrue(l.startswith("2 "), l)
        self.assertIn("failed=2;;1", l)
        self.assertIn("lukd queue ls / rm", l)
        self.assertNotIn("retry", l)
        self.assertNotIn("\n", l)
        self.assertEqual(len(l.splitlines()), 1)
        self.assertIn("boom bad pipe", l)
        self.assertNotIn("x" * 201, l)

    def test_failed_no_expectation(self):
        l = self.one([entry(failed=1)], conf=None)
        self.assertTrue(l.startswith("2 "), l)
        self.assertIn("no error recorded", l)

    def test_no_expectation_ok(self):
        l = self.check([entry(pipeline="other", sender="x")], conf=CONF)[0]
        self.assertTrue(l.startswith('0 "luk other x" age=21600|'), l)
        self.assertIn("last success 6h 0m ago", l)

    def test_no_expectation_never_ok(self):
        l = self.check([entry(pipeline="other", last_success="", size=0, failed=None)], conf=CONF)[0]
        self.assertTrue(l.startswith('0 "luk other replica.aws.example.net" size=0 '), l)

    def test_no_metrics_dash(self):
        l = self.one([{"pipeline": "p", "sender": "s"}], conf=None)
        self.assertTrue(l.startswith('0 "luk p s" - '), l)

    def test_never_received(self):
        out = self.check([entry(pipeline="other")], conf=CONF)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[1], '2 "luk devdb replica.*.example.net" - never received')

    def test_fnmatch(self):
        l = self.one([entry(sender="replica.eu.example.net", size=1)])
        self.assertTrue(l.startswith("1 "), l)  # matched, size warn
        out = self.check([entry(sender="primary.example.net")])
        self.assertEqual(len(out), 2)  # no match -> informational + never received
        self.assertTrue(out[0].startswith("0 "), out)

    def test_pattern_case_sensitive(self):
        out = self.check([entry(sender="REPLICA.aws.example.net")])
        self.assertEqual(len(out), 2)

    def test_first_match_wins(self):
        conf = "[devdb replica.*]\nwarn_age=1h\ncrit_age=2h\n[devdb *]\nwarn_age=9d\ncrit_age=10d\n"
        l = self.one([entry()], conf=conf)
        self.assertTrue(l.startswith("2 "), l)

    def test_name_sanitized(self):
        l = self.one([entry(pipeline="a b", sender="h\x01 1:2")], conf=None)
        self.assertTrue(l.startswith('0 "luk a_b h__1:2" '), l)

    def test_future_timestamp_age_zero(self):
        l = self.one([entry(last_success="2026-10-01T00:00:00Z")], conf=None)
        self.assertIn("age=0", l)

    def test_bad_timestamp(self):
        l = self.one([entry(last_success="nope")])
        self.assertTrue(l.startswith("3 "), l)

    def test_multiple_entries(self):
        out = self.check([entry(), entry(sender="replica.b.example.net", size=1)])
        self.assertEqual([o[0] for o in out], ["0", "1"])

    def test_metrics_syntax(self):
        for l in self.check([entry(), entry(failed=3), entry(last_success="")]):
            m = l.split('" ', 1)[1].split(" ", 1)[0]
            for part in m.split("|"):
                self.assertRegex(part, r"^[a-z]+=\d+(;\d*){0,4}$")


def watch(**kw):
    w = {"storage": "archive", "rule": 1, "pipeline": "nightly", "origin": "db1-prod", "file": "db.sql",
         "state": "OK", "message": "db1-prod/db.sql: last copy 3h ago, 4G",
         "newest_received": "2026-09-30T09:00:00Z", "size": 4 * 1024**3, "copies": 3,
         "evaluated": "2026-09-30T11:59:00Z"}
    w.update(kw)
    return w


class TestWatch(Base):
    def test_object_with_pipelines_and_watch(self):
        out = self.check({"pipelines": [entry()], "watch": [watch()]})
        self.assertEqual(len(out), 2, out)
        self.assertTrue(out[0].startswith('0 "luk devdb replica.aws.example.net" '), out)
        self.assertEqual(out[1], '0 "luk watch archive nightly db1-prod/db.sql" age=10800|size=4294967296 '
                                 'db1-prod/db.sql: last copy 3h ago, 4G')

    def test_states(self):
        for state, want in (("OK", "0"), ("WARN", "1"), ("CRIT", "2"), ("BOGUS", "3"), (None, "3")):
            l = self.one({"pipelines": [], "watch": [watch(state=state)]}, conf=None)
            self.assertEqual(l[0], want, (state, l))

    def test_crit_message(self):
        msg = "db1-prod/db.sql: 980M below min 2G; last copy 31h ago (every 26h)"
        l = self.one({"pipelines": [], "watch": [watch(state="CRIT", message=msg, size=980 * 1024**2,
                                                       newest_received="2026-09-29T05:00:00Z")]}, conf=None)
        self.assertEqual(l, '2 "luk watch archive nightly db1-prod/db.sql" age=111600|size=1027604480 ' + msg)

    def test_rule_without_series(self):
        w = {"storage": "archive", "rule": 2, "pipeline": "", "origin": "", "file": "", "state": "WARN",
             "message": "rule 2 (origin *-stage): no series matches", "size": 0, "copies": 0,
             "evaluated": "2026-09-30T11:59:00Z"}
        l = self.one({"pipelines": [], "watch": [w]}, conf=None)
        self.assertEqual(l, '1 "luk watch archive rule 2" - rule 2 (origin *-stage): no series matches')

    def test_series_without_copy(self):
        l = self.one({"pipelines": [], "watch": [watch(state="CRIT", newest_received=None, size=0, copies=0,
                                                       message="db1-prod/db.sql: no copy with a readable received time")]}, conf=None)
        self.assertTrue(l.startswith('2 "luk watch archive nightly db1-prod/db.sql" - '), l)

    def test_stale_evaluation(self):
        l = self.one({"pipelines": [], "watch": [watch(evaluated="2026-09-30T11:49:00Z")]}, conf=None)
        self.assertTrue(l.startswith("3 "), l)
        self.assertIn("evaluated 11m ago, is lukd process running? last: db1-prod/db.sql", l)
        l = self.one({"pipelines": [], "watch": [watch(evaluated="2026-09-30T11:50:00Z")]}, conf=None)
        self.assertTrue(l.startswith("0 "), l)

    def test_not_evaluated_or_bad_time(self):
        l = self.one({"pipelines": [], "watch": [watch(evaluated="")]}, conf=None)
        self.assertTrue(l.startswith("3 ") and "not evaluated" in l, l)
        l = self.one({"pipelines": [], "watch": [watch(newest_received="soon")]}, conf=None)
        self.assertTrue(l.startswith('3 "luk watch archive nightly db1-prod/db.sql" - bad timestamp'), l)

    def test_names_sanitized(self):
        l = self.one({"pipelines": [], "watch": [watch(storage="a b", pipeline="", file="my db.sql\x01",
                                                       message="x|y\nz")]}, conf=None)
        self.assertTrue(l.startswith('0 "luk watch a_b - db1-prod/my_db.sql_" '), l)
        self.assertTrue(l.endswith(" x y z"), l)
        self.assertEqual(len(l.splitlines()), 1)

    def test_watch_optional_and_old_array(self):
        self.assertEqual(len(self.check({"pipelines": [entry()]})), 1)
        self.assertEqual(len(self.check([entry()])), 1)

    def test_invalid_watch(self):
        for raw in ('{"pipelines": [], "watch": {}}', '{"pipelines": [], "watch": [1]}', '{"watch": []}', '"x"'):
            l = self.one(None, raw=raw)
            self.assertTrue(l.startswith('3 "luk status" - status.json invalid'), (raw, l))


class TestBadInput(Base):
    def test_status_missing(self):
        out = self.check(None)
        self.assertEqual(out, ['3 "luk status" - status.json missing'])

    def test_status_invalid_json(self):
        l = self.one(None, raw="{nope")
        self.assertTrue(l.startswith('3 "luk status" - status.json unreadable'), l)

    def test_status_not_array(self):
        l = self.one(None, raw='{"a": 1}')
        self.assertTrue(l.startswith('3 "luk status"'), l)
        l = self.one(None, raw="[1, 2]")
        self.assertTrue(l.startswith('3 "luk status"'), l)

    def test_empty_array_reports_expectations(self):
        out = self.check([], conf=CONF)
        self.assertEqual(out, ['2 "luk devdb replica.*.example.net" - never received'])

    def test_empty_array_no_conf(self):
        self.assertEqual(self.check([], conf=None), [])

    def test_conf_malformed(self):
        for conf in ("garbage without section", "[nospace]\nwarn_age=1h",
                     "[devdb x]\nwarn_age=soon", "[devdb x]\nbogus=1",
                     "[devdb x]\nmin_size=1X", "[devdb x]\n[devdb x]\n"):
            l = self.one([entry()], conf=conf)
            self.assertTrue(l.startswith('3 "luk status" - check.conf: '), (conf, l))

    def test_conf_missing_is_ok(self):
        l = self.one([entry()], conf=None)
        self.assertTrue(l.startswith("0 "), l)

    def test_wrong_types_ignored(self):
        l = self.one([entry(size="big", failed="x")], conf=None)
        self.assertNotIn("size=", l)
        self.assertNotIn("failed=", l)
        self.assertTrue(l.startswith("0 "), l)


if __name__ == "__main__":
    unittest.main()
