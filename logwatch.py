#!/usr/bin/env python3
"""logwatch - SSH auth.log anomaly detector.

Original code, stdlib only. Parses OpenSSH auth.log lines and flags
brute-force bursts and logins that succeed right after a burst.
"""
import argparse
import json
import re
from collections import defaultdict

FAILED = re.compile(
    r"(?P<ts>\w{3}\s+\d+ \d\d:\d\d:\d\d).*Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
ACCEPTED = re.compile(
    r"(?P<ts>\w{3}\s+\d+ \d\d:\d\d:\d\d).*Accepted \S+ for "
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

def _minutes(ts):
    # 'Nov 14 03:12:55' -> minutes in the day (month/day kept for sorting)
    months = {m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
    mon, day, clock = ts.split()
    h, m, s = map(int, clock.split(":"))
    return (((months[mon] * 31) + int(day)) * 24 + h) * 60 + m + s / 60.0

def parse(text):
    """Return (events, unparsed_count). events: (minute, kind, user, ip)."""
    events = []
    skipped = 0
    for line in text.splitlines():
        for rx, kind in ((FAILED, "fail"), (ACCEPTED, "ok")):
            m = rx.search(line)
            if m:
                events.append((_minutes(m["ts"]), kind, m["user"], m["ip"]))
                break
        else:
            if line.strip():
                skipped += 1
    return events, skipped

def analyze(text, burst=5, window=10):
    """Flag IPs with >=burst failures inside `window` minutes, and any
    accepted login from an IP that had a failing burst earlier."""
    events, skipped = parse(text)
    events.sort(key=lambda e: e[0])
    fails = defaultdict(list)
    accepted = defaultdict(list)
    for minute, kind, user, ip in events:
        (fails if kind == "fail" else accepted)[ip].append((minute, user))

    alerts = []
    flagged = {}
    for ip, tries in fails.items():
        times = [t for t, _ in tries]
        users = sorted({u for _, u in tries})
        worst = 0
        for i, start in enumerate(times):
            j = i
            while j < len(times) and times[j] - start <= window:
                j += 1
            worst = max(worst, j - i)
        if worst >= burst:
            flagged[ip] = True
            alerts.append({"ip": ip, "kind": "brute-force burst",
                           "detail": f"{worst} failed logins within {window} min "
                                     f"(users tried: {', '.join(users[:6])})"})
    for ip, oks in accepted.items():
        if ip in flagged:
            first_ok = min(t for t, _ in oks)
            last_fail = max(t for t, _ in fails[ip])
            if first_ok >= last_fail - window:
                users = sorted({u for _, u in oks})
                alerts.append({"ip": ip, "kind": "success after burst",
                               "detail": f"accepted login for {', '.join(users)} "
                                         f"from the same IP after the burst - review now"})
    return {"alerts": alerts, "events": len(events),
            "unparsed_lines": skipped,
            "top_failers": sorted(((ip, len(v)) for ip, v in fails.items()),
                                  key=lambda x: -x[1])[:5]}

def main(argv=None):
    ap = argparse.ArgumentParser(description="SSH auth.log anomaly detector")
    ap.add_argument("logfile")
    ap.add_argument("--burst", type=int, default=5, help="failures that count as a burst")
    ap.add_argument("--window", type=int, default=10, help="burst window in minutes")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with open(a.logfile, encoding="utf-8", errors="replace") as f:
        report = analyze(f.read(), burst=a.burst, window=a.window)
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{report['events']} auth events parsed "
              f"({report['unparsed_lines']} other lines skipped)")
        if not report["alerts"]:
            print("no anomalies found")
        for al in report["alerts"]:
            print(f"  ! {al['kind']}: {al['ip']} - {al['detail']}")
        if report["top_failers"]:
            print("top failing IPs:")
            for ip, n in report["top_failers"]:
                print(f"    {ip}: {n} failures")
    return 1 if report["alerts"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
