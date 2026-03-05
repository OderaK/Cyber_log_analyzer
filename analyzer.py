#!/usr/bin/env python3
import argparse
import csv
import re
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Tuple


# Failed password for root from 203.0.113.5 port 45514 ssh2"
FAIL_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd.*Failed password.*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPT_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd.*Accepted password.*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

@dataclass(frozen=True)
class Event:
    ts: datetime
    ip: str
    kind: str  # "FAIL" or "ACCEPT"

def parse_ts(mon: str, day: str, timestr: str, year: int) -> datetime:
    m = MONTHS.get(mon)
    if m is None:
        raise ValueError(f"Unknown month: {mon}")
    return datetime(year, m, int(day), int(timestr[0:2]), int(timestr[3:5]), int(timestr[6:8]))

def load_events(path: str, year: int) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = FAIL_RE.search(line)
            if m:
                ts = parse_ts(m.group("mon"), m.group("day"), m.group("time"), year)
                events.append(Event(ts=ts, ip=m.group("ip"), kind="FAIL"))
                continue
            m = ACCEPT_RE.search(line)
            if m:
                ts = parse_ts(m.group("mon"), m.group("day"), m.group("time"), year)
                events.append(Event(ts=ts, ip=m.group("ip"), kind="ACCEPT"))
    events.sort(key=lambda e: e.ts)
    return events

def detect_bruteforce(events: List[Event], window_minutes: int, threshold: int) -> List[Tuple[str, datetime, datetime, int]]:
    """
    Returns alerts: (ip, window_start, window_end, fail_count_in_window)
    Sliding-window per IP over FAIL events.
    """
    fails_by_ip: defaultdict[str, List[datetime]] = defaultdict(list)
    for e in events:
        if e.kind == "FAIL":
            fails_by_ip[e.ip].append(e.ts)

    alerts: List[Tuple[str, datetime, datetime, int]] = []
    window = timedelta(minutes=window_minutes)

    for ip, times in fails_by_ip.items():
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                alerts.append((ip, times[left], times[right], count))
    # Deduplicate overlapping alerts a bit by keeping highest count per ip per end time
    alerts.sort(key=lambda t: (t[0], t[2], -t[3]))
    compact: List[Tuple[str, datetime, datetime, int]] = []
    seen = set()
    for a in alerts:
        key = (a[0], a[2])
        if key in seen:
            continue
        seen.add(key)
        compact.append(a)
    return compact

def detect_fail_then_accept(events: List[Event], lookback_minutes: int, min_fails: int) -> List[Tuple[str, datetime, datetime, int]]:
    """
    Alert when an IP has an ACCEPT event and had >= min_fails FAIL events in the previous lookback_minutes.
    Returns: (ip, first_fail_in_lookback, accept_time, fail_count)
    """
    lookback = timedelta(minutes=lookback_minutes)

    # Track FAIL timestamps per IP
    fails_by_ip: defaultdict[str, List[datetime]] = defaultdict(list)
    for e in events:
        if e.kind == "FAIL":
            fails_by_ip[e.ip].append(e.ts)

    alerts: List[Tuple[str, datetime, datetime, int]] = []
    for e in events:
        if e.kind != "ACCEPT":
            continue
        ip = e.ip
        fail_times = fails_by_ip.get(ip, [])
        if not fail_times:
            continue

        # Count FAILs within [accept_time - lookback, accept_time]
        start = e.ts - lookback
        # Since fail_times are sorted (events sorted), do a simple scan
        window_fails = [t for t in fail_times if start <= t <= e.ts]
        if len(window_fails) >= min_fails:
            alerts.append((ip, window_fails[0], e.ts, len(window_fails)))

    return alerts

def print_summary(events: List[Event], top_n: int) -> None:
    fail_counts = Counter(e.ip for e in events if e.kind == "FAIL")
    accept_counts = Counter(e.ip for e in events if e.kind == "ACCEPT")

    print("\n== Summary ==")
    print(f"Total events parsed: {len(events)}")
    print(f"Total FAIL: {sum(fail_counts.values())} | Total ACCEPT: {sum(accept_counts.values())}")

    print(f"\nTop {top_n} IPs by FAIL count:")
    for ip, c in fail_counts.most_common(top_n):
        print(f"  {ip:15s}  FAIL={c:3d}  ACCEPT={accept_counts.get(ip, 0):3d}")

def write_csv(alerts: List[Tuple[str, datetime, datetime, int]], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "window_start", "window_end", "fail_count"])
        for ip, ws, we, cnt in alerts:
            w.writerow([ip, ws.isoformat(sep=" "), we.isoformat(sep=" "), cnt])

def main() -> int:
    ap = argparse.ArgumentParser(description="Detect brute-force style SSH login failures from auth logs.")
    ap.add_argument("logfile", help="Path to auth log file (e.g., /var/log/auth.log or sample_auth.log)")
    ap.add_argument("--year", type=int, default=datetime.now().year, help="Year for timestamps (syslog lines omit year).")
    ap.add_argument("--window", type=int, default=10, help="Time window in minutes (default: 10).")
    ap.add_argument("--threshold", type=int, default=5, help="Failures in window to alert (default: 5).")
    ap.add_argument("--top", type=int, default=10, help="Top N IPs to show (default: 10).")
    ap.add_argument("--csv", dest="csv_path", default=None, help="Optional output CSV path for alerts.")

    ap.add_argument("--lookback", type=int, default=30, help="Minutes to look back for FAILs before an ACCEPT (default: 30).")
    ap.add_argument("--min-fails", type=int, default=3, help="Minimum FAILs before ACCEPT to alert (default: 3).")
    args = ap.parse_args()

    events = load_events(args.logfile, args.year)
    if not events:
        print("No sshd FAIL/ACCEPT events matched. Check log format or regex patterns.")
        return 2

    print_summary(events, args.top)
    alerts = detect_bruteforce(events, args.window, args.threshold)

    print("\n== Alerts ==")
    if not alerts:
        print(f"No IP exceeded threshold={args.threshold} within window={args.window} minutes.")
    else:
        for ip, ws, we, cnt in alerts:
            print(f"ALERT: {ip} had {cnt} FAILs between {ws} and {we} (window={args.window}m)")

    if args.csv_path:
        write_csv(alerts, args.csv_path)
        print(f"\nWrote alerts to CSV: {args.csv_path}")

    fta = detect_fail_then_accept(events, args.lookback, args.min_fails)

    print("\n== FAIL -> ACCEPT Alerts ==")
    if not fta:
        print(f"No ACCEPT events preceded by >= {args.min_fails} FAILs within {args.lookback} minutes.")
    else:
        for ip, first_fail, accept_ts, cnt in fta:
            print(f"ALERT: {ip} had {cnt} FAILs from {first_fail} then ACCEPT at {accept_ts} (lookback={args.lookback}m)")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())