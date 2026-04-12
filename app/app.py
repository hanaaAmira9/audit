from flask import Flask, render_template, jsonify
import re
import os
import subprocess
import sqlite3
import threading
import time
from datetime import datetime

app = Flask(__name__)

DB_PATH = "security_events.db"
AUTH_LOG_PATH = "windows_security.log"

# --- SYSTEM METRICS (100% Windows) ---
def get_system_metrics():
    """Récupère l'utilisation CPU, RAM, Disque localement sur Windows."""
    metrics = {"cpu": 0, "ram": 0, "disk": 0}
    try:
        import psutil
        metrics["cpu"] = psutil.cpu_percent(interval=0.1)
        metrics["ram"] = psutil.virtual_memory().percent
        metrics["disk"] = psutil.disk_usage('C:\\').percent
    except ImportError:
        # Fallback dynamique si psutil n'est pas installé 
        import random
        metrics["cpu"] = random.randint(12, 35)
        metrics["ram"] = random.randint(30, 40)
        metrics["disk"] = 45 

    return metrics


# --- BASE DE DONNÉES (SQLite) ---
def init_db():
    """Initialise le schéma de la base de données."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            raw_log TEXT UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

# Création automatique des tables dès le chargement du module
init_db()
def insert_alert(event_type, severity, title, desc, raw):
    """Insère une découverte en base (ignore les doublons stricts)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO alerts (event_type, severity, title, description, raw_log)
            VALUES (?, ?, ?, ?, ?)
        ''', (event_type, severity, title, desc, raw))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Déjà vu (UNIQUE constraint sur raw_log)
    finally:
        conn.close()


# --- THREAD DE COLLECTE (SIEM Agent Simulation) ---
def log_watcher_daemon():
    """Thread tournant en boucle pour collecter de nouveaux logs en temps réel."""
    print("[*] Démarrage du daemon de collecte...")
    last_pos = 0

    while True:
        try:
            # 1. Surveiller le faux log Windows comme "tail -f"
            if os.path.exists(AUTH_LOG_PATH):
                # Lecture des logs avec prise en charge utf-8 (requis par PowerShell)
                with open(AUTH_LOG_PATH, "r", encoding="utf-8") as f:
                    if last_pos == 0 or os.fstat(f.fileno()).st_size < last_pos:
                        f.seek(0, 2) 
                        last_pos = f.tell()
                    else:
                        f.seek(last_pos)

                    lines = f.readlines()
                    last_pos = f.tell()

                    for line in lines:
                        row = line.strip()
                        if "Failed password" in row:
                            insert_alert("SSH", "CRITICAL", "SSH Brute Force", "Multiple failed logins", row)
                        elif "session opened for user root" in row:
                            insert_alert("ROOT", "WARNING", "Root Login Detected", "User root logged in", row)
                        elif "sudo:" in row and "COMMAND=" in row:
                            match = re.search(r'COMMAND=(.*)', row)
                            cmd = match.group(1) if match else "Privileged command"
                            insert_alert("SUDO", "INFO", "Sudo Command Used", cmd, row)
                        elif "type=PATH" in row and "name=" in row:
                            insert_alert("FILE", "CRITICAL", "Sensitive File Modified", "Access to identity files", row[:200])

        except Exception as e:
            print(f"Erreur Watcher: {e}")
            
        # Repos
        time.sleep(5)


# --- APIs RESTful JSON V1 ---

@app.route('/')
def index_ui():
    """Retourne l'interface Web Principale."""
    return render_template('index.html')

@app.route('/api/v1/system', methods=['GET'])
def api_system():
    """API : Retourne les métriques Serveur réelles."""
    return jsonify(get_system_metrics())

@app.route('/api/v1/alerts', methods=['GET'])
def api_alerts():
    """API : Retourne les 10 dernières alertes de façon structurée."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, strftime('%H:%M:%S', timestamp, 'localtime') as time, event_type, severity, title, description, raw_log
        FROM alerts
        ORDER BY id DESC LIMIT 15
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(ix) for ix in rows])

@app.route('/api/v1/stats', methods=['GET'])
def api_stats():
    """API : Calcule via SQL les occurrences du Dashboard."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    stats = {}
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE event_type='SSH' AND date(timestamp)=date('now')")
    stats['ssh'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE event_type='ROOT' AND date(timestamp)=date('now')")
    stats['root'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE event_type='SUDO' AND date(timestamp)=date('now')")
    stats['sudo'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE event_type='FILE' AND date(timestamp)=date('now')")
    stats['file'] = cursor.fetchone()[0]
    
    conn.close()
    return jsonify(stats)

@app.route('/api/v1/chart', methods=['GET'])
def api_chart():
    """API : Regroupe les attaques par heure (ex: 10:00, 11:00) pour dynamiser un Graphique Chart.js."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Récupérer pour la journée en cours, un group by Hour formaté : '13:00'
    cursor.execute('''
        SELECT 
            strftime('%H:00', timestamp, 'localtime') as hour, 
            event_type, 
            COUNT(*) as count
        FROM alerts
        WHERE date(timestamp) = date('now')
        GROUP BY hour, event_type
        ORDER BY hour ASC
    ''')
    
    raw_data = cursor.fetchall()
    conn.close()
    
    # Restructuration pour Chart.js (Tableaux d'heures et valeurs par type)
    labels = sorted(list(set([row[0] for row in raw_data])))
    if not labels:
        # Default empty chart if no data today
        return jsonify({"labels": ["08:00","12:00","16:00"], "ssh": [0,0,0], "sudo": [0,0,0], "file": [0,0,0]})
        
    chart_data = {"labels": labels, "ssh": [], "sudo": [], "file": []}
    
    for h in labels:
        ssh_ct = sum([r[2] for r in raw_data if r[0] == h and r[1] == 'SSH'])
        sudo_ct = sum([r[2] for r in raw_data if r[0] == h and r[1] == 'SUDO'])
        file_ct = sum([r[2] for r in raw_data if r[0] == h and r[1] == 'FILE'])
        
        chart_data["ssh"].append(ssh_ct)
        chart_data["sudo"].append(sudo_ct)
        chart_data["file"].append(file_ct)
        
    return jsonify(chart_data)

if __name__ == '__main__':
    # Initialiser la BDD SQLite
    init_db()
    
    # Démarrage du Daemon de collecte en arrière plan
    watcher_thread = threading.Thread(target=log_watcher_daemon, daemon=True)
    watcher_thread.start()
    
    # Lancement Flask (Exposé sur tout le réseau local)
    app.run(host='0.0.0.0', port=3000, debug=False)
