"""Generates realistic attack logs (SSH brute force -> compromise -> data theft, port scan, web scan)
so the system can be demonstrated and tested without a real attacker."""
import random
from datetime import datetime, timedelta

import config

ATTACKER = "185.220.101.45"
SCANNER = "45.155.205.9"
WEB_SCANNER = "103.77.192.19"


def _sys(dt, host, prog, msg):
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} {host} {prog}: {msg}"


def _apache(dt, ip, req, status, size, user="-"):
    return f'{ip} - {user} [{dt:%d/%b/%Y:%H:%M:%S} +0530] "{req} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'


def attack_lines(base):
    """Attack scenario that ENDS at `base` (so it is 'live' when base = now)."""
    L = []
    t = base - timedelta(minutes=4)
    users = ["admin", "root", "oracle", "test", "ubuntu", "postgres"]
    for i in range(32):  # SSH brute force
        t += timedelta(seconds=1.2)
        L.append((t, _sys(t, "college-srv", "sshd[2211]", f"Failed password for invalid user {users[i % 6]} "
                                                          f"from {ATTACKER} port {40000 + i} ssh2")))
    t += timedelta(seconds=3)  # attacker gets in
    L.append((t, _sys(t, "college-srv", "sshd[2230]", f"Accepted password for ubuntu from {ATTACKER} port 40100 ssh2")))
    t += timedelta(seconds=20)
    L.append((t, _sys(t, "college-srv", "useradd[2290]", "new user: name=svc_backup, UID=1003, GID=1003, home=/home/svc_backup")))
    t += timedelta(seconds=10)  # data theft
    L.append((t, _apache(t, ATTACKER, "GET /exports/students_db.zip", 200, 734003200)))
    t += timedelta(seconds=15)
    L.append((t, _apache(t, ATTACKER, "GET /exports/faculty_records.zip", 200, 402653184)))
    s = base - timedelta(minutes=3)
    for i in range(45):  # port scan
        s += timedelta(seconds=0.4)
        L.append((s, _sys(s, "college-fw", "kernel", f"[UFW BLOCK] IN=eth0 OUT= SRC={SCANNER} DST=10.0.0.5 "
                                                     f"PROTO=TCP SPT=4444 DPT={20 + i * 7}")))
    w = base - timedelta(minutes=2)
    for i in range(30):  # web scanner
        w += timedelta(seconds=0.7)
        L.append((w, _apache(w, WEB_SCANNER, f"GET /wp-admin/setup{i}.php", 404, 196)))
    # benign background
    for i in range(8):
        b = base - timedelta(minutes=random.randint(1, 10), seconds=random.randint(0, 59))
        L.append((b, _apache(b, f"192.168.1.{10 + i}", "GET /index.html", 200, 5120)))
    b = base - timedelta(minutes=6)
    L.append((b, _sys(b, "college-srv", "sshd[2100]", "Accepted publickey for varsha from 192.168.1.20 port 51200 ssh2")))
    L.sort(key=lambda x: x[0])
    return [line for _, line in L]


def write_sample(path=None, day=None):
    """A full 'day' of logs (with an attack at 02:xx) for the Upload demo and the ML detector."""
    random.seed(7)
    day = day or datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    lines = []
    for h in range(24):  # normal traffic from many clients across the day
        for _ in range(random.randint(8, 22)):
            ip = random.choice([f"192.168.1.{random.randint(10, 60)}", f"10.0.0.{random.randint(2, 40)}"])
            t = day + timedelta(hours=h, minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            lines.append((t, _apache(t, ip, random.choice(["GET /index.html", "GET /notes.pdf", "GET /login", "POST /api/attendance"]),
                                     random.choice([200, 200, 200, 304]), random.randint(500, 90000))))
        for u in random.sample(["varsha", "priya", "arjun", "meera"], 2):
            t = day + timedelta(hours=h, minutes=random.randint(0, 59))
            if 8 <= h <= 20:
                lines.append((t, _sys(t, "college-srv", "sshd[900]", f"Accepted publickey for {u} from 192.168.1.{random.randint(10, 60)} port 5{random.randint(1000, 9999)} ssh2")))
    # a chatty client that fails a few times (normal typos)
    t = day + timedelta(hours=11, minutes=5)
    for i in range(3):
        lines.append((t + timedelta(seconds=i * 8), _sys(t, "college-srv", "sshd[950]", "Failed password for priya from 192.168.1.33 port 50011 ssh2")))
    attack = attack_lines(day + timedelta(hours=2, minutes=40))
    path = path or (config.SAMPLE_DIR / "demo_attack_day.log")
    lines.sort(key=lambda x: x[0])
    with open(path, "w") as f:
        for _, l in lines:
            f.write(l + "\n")
        for l in attack:
            f.write(l + "\n")
    return path
