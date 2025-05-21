"""Template script for IT 390R log‑analysis lab

Students: complete the **TODO** sections in `analyze_failed_logins` and
`analyze_successful_creds`.  All other tasks already work, so you can run the
script right away to explore the output format.

Run examples
------------
# Once you fill in the failed‑login logic
python analyze_log.py cowrie-tiny.log --task failed-logins --min-count 5

# Connection volume task (already functional)
python analyze_log.py cowrie-tiny.log --task connections

# Identify bot clients by shared fingerprint (already functional)
python analyze_log.py cowrie-tiny.log --task identify-bots --min-ips 3
"""

import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[.*?/.*?\] failed"
)

NEW_CONN_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

# ── Helper to print tables ──────────────────────────────────────────────────

def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    """Nicely format a Counter as a two‑column table."""
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

# ── TODO Task 1: fill this in ───────────────────────────────────────────────

# regex assisted by ChatGPT
def analyze_failed_logins(path: str, min_count: int):
    """Parse *failed* SSH login attempts and show a count per source IP."""
    counter = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FAILED_LOGIN_PATTERN.search(line)
            if m:
                ip = m.group("ip")
                counter[ip] += 1
    filtered = Counter({ip: cnt for ip, cnt in counter.items() if cnt >= min_count})
    print(f"Failed logins from IPs (count ≥ {min_count})")
    _print_counter(filtered, "IP Address", "Count")


# ── Task 2 (already done) ───────────────────────────────────────────────────

def connections(path: str):
    per_min = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = NEW_CONN_PATTERN.search(line)
            if m:
                dt = datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                per_min[dt.strftime("%Y-%m-%d %H:%M")] += 1
    print("Connections per minute")
    _print_counter(per_min, "Timestamp", "Count", sort_keys=True)

# ── TODO Task 3: fill this in ───────────────────────────────────────────────

# regex assisted by ChatGPT
def analyze_successful_creds(path: str):
    """Display username/password pairs that *succeeded* and how many unique IPs used each."""
    cred_map = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = SUCCESS_LOGIN_PATTERN.search(line)
            if m:
                user = m.group("user")
                pw = m.group("pw")
                ip = m.group("ip")
                cred_map[(user, pw)].add(ip)
    sorted_creds = sorted(cred_map.items(), key=lambda item: len(item[1]), reverse=True)
    width_user = max(len(user) for (user, _), _ in sorted_creds) if sorted_creds else len("Username")
    width_pw = max(len(pw) for (_, pw), _ in sorted_creds) if sorted_creds else len("Password")
    print(f"{'Username':<{width_user}} {'Password':<{width_pw}} {'IP_Count':>9}")
    print("-" * (width_user + width_pw + 11))
    for (user, pw), ips in sorted_creds:
        print(f"{user:<{width_user}} {pw:<{width_pw}} {len(ips):>9}")


# ── Task 4 (bot fingerprints) already implemented ───────────────────────────

def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FINGERPRINT_PATTERN.search(line)
            if m:
                fp_map[m.group("fp")].add(m.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"Fingerprints seen from ≥ {min_ips} unique IPs")
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")


#---- Extra Credit Task ------------------------------------------------------

# regex assisted by ChatGPT
def session_times(path: str):
    session_start_pattern = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
        r"\[HoneyPotSSHTransport,(?P<cid>\d+),(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?login attempt \[.*?/.*?\] succeeded"
    )
    session_end_pattern = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
        r"\[HoneyPotSSHTransport,(?P<cid>\d+),(?P<ip>\d+\.\d+\.\d+\.\d+)\] Connection lost"
    )

    sessions = {}
    durations = []

    with open(path, encoding="utf-8") as fp:
        for line in fp:
            start = session_start_pattern.search(line)
            if start:
                key = (start.group("cid"), start.group("ip"))
                ts = datetime.fromisoformat(start.group("ts"))
                sessions[key] = ts
                continue

            end = session_end_pattern.search(line)
            if end:
                key = (end.group("cid"), end.group("ip"))
                if key in sessions:
                    start_time = sessions.pop(key)
                    end_time = datetime.fromisoformat(end.group("ts"))
                    duration = (end_time - start_time).total_seconds()
                    if duration >= 0:
                        durations.append(duration)

    if durations:
        print("Session durations (in seconds):")
        print(f"  Min: {min(durations):.2f}")
        print(f"  Avg: {sum(durations)/len(durations):.2f}")
        print(f"  Max: {max(durations):.2f}")
    else:
        print("No complete sessions found.")


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cowrie log analyzer — student template")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--task",
                        required=True,
                        choices=["failed-logins", "connections",
                                 "successful-creds", "identify-bots", "session-times"],
                        help="Which analysis to run")
    parser.add_argument("--min-count", type=int, default=1,
                        help="Min events to report (failed-logins)")
    parser.add_argument("--min-ips", type=int, default=3,
                        help="Min IPs per fingerprint (identify-bots)")
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "connections":
        connections(args.logfile)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)
    elif args.task == "session-times":
        session_times(args.logfile)


if __name__ == "__main__":
    main()
