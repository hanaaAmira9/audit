from flask import Flask, render_template, jsonify
import os
import re
import sqlite3
import threading
import time
import subprocess
from datetime import datetime

app = Flask(__name__)

DB_PATH = "security_events.db"
AUTH_LOG_PATH = "/var/log/auth.log"
POLL_INTERVAL = 3

# État simple en mémoire pour éviter de relire les mêmes logs
state = {
    "auth_offset": 0,
}

# Accepte :
# - Failed password for root from 192.168.1.10 port 22 ssh2
# - Failed password for invalid user fakeuser from ::1 port 54922 ssh2
SSH_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)( port (?P<port>\d+))?( ssh2)?",
    re.IGNORECASE
)

SUDO_CMD_RE = re.compile(r"sudo: .*COMMAND=(?P<cmd>.+)")
ROOT_SESSION_RE = re.compile(r"session opened for user root", re.IGNORECASE)


# --- BASE DE DONNÉES ---
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            raw_log TEXT NOT NULL UNIQUE
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_type ON alerts(event_type)")

    conn.commit()
    conn.close()


def insert_alert(source, event_type, severity, title, description, raw_log, timestamp=None):
    if not raw_log or not raw_log.strip():
        return

    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO alerts (timestamp, source, event_type, severity, title, description, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ts, source, event_type, severity, title, description, raw_log))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


# --- MÉTRIQUES SYSTÈME ---
def get_system_metrics():
    metrics = {"cpu": 0.0, "ram": 0.0, "disk": 0.0}

    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            mem = {}
            for line in lines:
                parts = line.replace(":", "").split()
                if len(parts) >= 2:
                    mem[parts[0]] = int(parts[1])

            mem_total = mem.get("MemTotal", 0)
            mem_free = mem.get("MemFree", 0)
            buffers = mem.get("Buffers", 0)
            cached = mem.get("Cached", 0)

            if mem_total > 0:
                used = mem_total - (mem_free + buffers + cached)
                metrics["ram"] = round((used / mem_total) * 100, 1)

        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total > 0:
            metrics["disk"] = round(((total - free) / total) * 100, 1)

        if os.path.exists("/proc/stat"):
            with open("/proc/stat", "r", encoding="utf-8", errors="ignore") as f:
                cpu_line = f.readline().split()[1:]
            cpu_data = [float(x) for x in cpu_line]
            total_time = sum(cpu_data)
            idle_time = cpu_data[3]
            if total_time > 0:
                metrics["cpu"] = round(100 - ((idle_time / total_time) * 100), 1)

    except Exception as e:
        print(f"[metrics] error: {e}")

    return metrics


# --- COLLECTE auth.log ---
def process_auth_line(line):
    row = line.strip()
    if not row:
        return

    m_ssh = SSH_FAILED_RE.search(row)
    if m_ssh:
        user = m_ssh.group("user")
        ip = m_ssh.group("ip")
        port = m_ssh.group("port") or "unknown"

        insert_alert(
            source="auth.log",
            event_type="SSH",
            severity="CRITICAL",
            title="SSH Failed Login",
            description=f"Failed SSH login for user {user} from {ip} on port {port}",
            raw_log=row,
        )
        return

    m_sudo = SUDO_CMD_RE.search(row)
    if m_sudo:
        insert_alert(
            source="auth.log",
            event_type="SUDO",
            severity="INFO",
            title="Sudo Command Used",
            description=m_sudo.group("cmd").strip(),
            raw_log=row,
        )
        return

    if ROOT_SESSION_RE.search(row):
        insert_alert(
            source="auth.log",
            event_type="ROOT",
            severity="WARNING",
            title="Root Session Opened",
            description="Privileged root session opened via sudo/PAM",
            raw_log=row,
        )


def poll_auth_log():
    if not os.path.exists(AUTH_LOG_PATH):
        return

    with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        current_size = os.fstat(f.fileno()).st_size
        last_offset = state.get("auth_offset", 0)

        # Si logrotate, on repart au début
        if last_offset > current_size:
            last_offset = 0

        # Important :
        # au premier démarrage, on lit aussi les lignes déjà présentes
        f.seek(last_offset)
        lines = f.readlines()
        state["auth_offset"] = f.tell()

    for line in lines:
        process_auth_line(line)


# --- COLLECTE auditd / ausearch ---
def poll_audit_events():
    try:
        result = subprocess.run(
            ["ausearch", "-k", "identity", "-m", "PATH", "-i", "-ts", "recent"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            if result.stderr.strip():
                print(f"[audit] {result.stderr.strip()}")
            return

        if not result.stdout.strip():
            return

        chunks = [c.strip() for c in result.stdout.split("----") if c.strip()]
        for chunk in chunks:
            if "type=PATH" not in chunk and "name=" not in chunk:
                continue

            clean_chunk = " ".join(chunk.split())
            insert_alert(
                source="auditd",
                event_type="FILE",
                severity="CRITICAL",
                title="Sensitive File Access",
                description="Access detected on monitored identity file",
                raw_log=clean_chunk[:1200],
            )

    except Exception as e:
        print(f"[audit] error: {e}")


# --- THREAD DE COLLECTE ---
def log_watcher_daemon():
    print("[*] Démarrage du daemon de collecte...")

    while True:
        try:
            poll_auth_log()
            poll_audit_events()
        except Exception as e:
            print(f"[watcher] error: {e}")

        time.sleep(POLL_INTERVAL)


# --- ROUTES FLASK ---
@app.route("/")
def index_ui():
    return render_template("index.html")


@app.route("/api/v1/system", methods=["GET"])
def api_system():
    return jsonify(get_system_metrics())


@app.route("/api/v1/alerts", methods=["GET"])
def api_alerts():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            strftime('%H:%M:%S', timestamp, 'localtime') AS time,
            source,
            event_type,
            severity,
            title,
            description,
            raw_log
        FROM alerts
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/v1/stats", methods=["GET"])
def api_stats():
    conn = get_db()
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT event_type, COUNT(*) AS total
        FROM alerts
        WHERE date(timestamp) = date('now')
        GROUP BY event_type
    """).fetchall()

    conn.close()

    stats = {"ssh": 0, "root": 0, "sudo": 0, "file": 0}
    for row in rows:
        key = row["event_type"].lower()
        if key in stats:
            stats[key] = row["total"]

    return jsonify(stats)


@app.route("/api/v1/chart", methods=["GET"])
def api_chart():
    conn = get_db()
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT
            strftime('%H:00', timestamp, 'localtime') AS hour,
            event_type,
            COUNT(*) AS count
        FROM alerts
        WHERE date(timestamp) = date('now')
        GROUP BY hour, event_type
        ORDER BY hour ASC
    """).fetchall()

    conn.close()

    labels = sorted({row["hour"] for row in rows})
    if not labels:
        return jsonify({
            "labels": ["08:00", "12:00", "16:00"],
            "ssh": [0, 0, 0],
            "sudo": [0, 0, 0],
            "file": [0, 0, 0],
            "root": [0, 0, 0],
        })

    chart = {"labels": labels, "ssh": [], "sudo": [], "file": [], "root": []}
    for hour in labels:
        for event_type in ("SSH", "SUDO", "FILE", "ROOT"):
            count = sum(
                row["count"]
                for row in rows
                if row["hour"] == hour and row["event_type"] == event_type
            )
            chart[event_type.lower()].append(count)

    return jsonify(chart)


if __name__ == "__main__":
    init_db()

    watcher_thread = threading.Thread(target=log_watcher_daemon, daemon=True)
    watcher_thread.start()

    app.run(host="0.0.0.0", port=3000, debug=False)
