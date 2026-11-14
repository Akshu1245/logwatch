import unittest
from logwatch import parse, analyze

def fail(minute, user, ip, day="Nov 14"):
    h, m = divmod(minute, 60)
    return (f"{day} {h:02d}:{m:02d}:00 server sshd[1]: Failed password for "
            f"{user} from {ip} port 22 ssh2")

def ok(minute, user, ip, day="Nov 14"):
    h, m = divmod(minute, 60)
    return (f"{day} {h:02d}:{m:02d}:30 server sshd[1]: Accepted password for "
            f"{user} from {ip} port 22 ssh2")

class TestParse(unittest.TestCase):
    def test_parse_both_kinds(self):
        events, skipped = parse(fail(60, "root", "1.2.3.4") + "\n" +
                                ok(61, "akshay", "5.6.7.8") + "\nnoise line")
        self.assertEqual(len(events), 2)
        self.assertEqual(skipped, 1)

    def test_invalid_user_format(self):
        line = ("Nov 14 01:02:03 srv sshd[9]: Failed password for invalid user "
                "admin from 9.9.9.9 port 51322 ssh2")
        events, _ = parse(line)
        self.assertEqual(events[0][2], "admin")
        self.assertEqual(events[0][3], "9.9.9.9")

class TestAnalyze(unittest.TestCase):
    def test_burst_flagged(self):
        log = "\n".join(fail(100 + i, "root", "1.2.3.4") for i in range(6))
        r = analyze(log, burst=5, window=10)
        self.assertEqual(r["alerts"][0]["kind"], "brute-force burst")

    def test_slow_drip_not_flagged(self):
        log = "\n".join(fail(i * 60, "root", "1.2.3.4") for i in range(6))
        r = analyze(log, burst=5, window=10)
        self.assertEqual(r["alerts"], [])

    def test_success_after_burst(self):
        lines = [fail(100 + i, "root", "1.2.3.4") for i in range(6)]
        lines.append(ok(108, "akshay", "1.2.3.4"))
        r = analyze("\n".join(lines), burst=5, window=10)
        kinds = {a["kind"] for a in r["alerts"]}
        self.assertIn("success after burst", kinds)

    def test_clean_success_not_flagged(self):
        log = ok(100, "akshay", "5.6.7.8")
        r = analyze(log)
        self.assertEqual(r["alerts"], [])

    def test_top_failers_sorted(self):
        lines = [fail(10 + i, "root", "1.1.1.1") for i in range(9)]
        lines += [fail(20 + i, "root", "2.2.2.2") for i in range(3)]
        r = analyze("\n".join(lines))
        self.assertEqual(r["top_failers"][0], ("1.1.1.1", 9))

    def test_empty_log(self):
        r = analyze("")
        self.assertEqual(r["events"], 0)
        self.assertEqual(r["alerts"], [])

if __name__ == "__main__":
    unittest.main()
