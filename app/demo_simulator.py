import sqlite3
import random
import time
from datetime import datetime, timedelta

DB_PATH = "security_events.db"

def init_db():
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

def inject_mock_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    event_types = [
        ("SSH", "CRITICAL", "SSH Brute Force", "Multiple failed logins from 192.168.1.", "sshd[102]: Failed password for root from 192.168.1."),
        ("ROOT", "WARNING", "Root Login Detected", "User root logged in successfully.", "session opened for user root by (uid=0)"),
        ("SUDO", "INFO", "Sudo Command Used", "Privileged command executed : sudo rm -rf", "sudo: admin : TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/bin/bash"),
        ("FILE", "CRITICAL", "Sensitive File Modified", "Access to /etc/shadow detected.", "type=SYSCALL msg=audit(161000): arch=c000003e syscall=2 success=yes exit=3 a0=7ff ... /etc/shadow")
    ]
    
    print("🚀 Début de l'injection d'attaques massives dans la base de données...")
    
    # On génère environ 30 attaques réparties sur les 5 dernières heures pour dynamiser le graphique
    for i in range(30):
        ev_type, severity, title, desc, raw = random.choice(event_types)
        
        # Mots aléatoires pour que chaque raw_log soit UNIQUE (sinon SQLite va ignorer les doublons)
        unique_raw = raw + str(random.randint(1000, 99999))
        
        # Timestamp aléatoire dans les 5 dernières heures
        random_minutes_ago = random.randint(1, 300)
        fake_time = datetime.now() - timedelta(minutes=random_minutes_ago)
        
        try:
            cursor.execute('''
                INSERT INTO alerts (timestamp, event_type, severity, title, description, raw_log)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (fake_time.strftime('%Y-%m-%d %H:%M:%S'), ev_type, severity, title, desc, unique_raw))
        except Exception as e:
            print("Erreur:", e)
            
    conn.commit()
    conn.close()
    print(f"✅ 30 Attaques injectées avec succès dans {DB_PATH}.")

if __name__ == "__main__":
    init_db()
    
    # 1. Insertion d'un grand volume dans le passé (pour le graphique)
    inject_mock_data()
    
    # 2. Simulation de direct (Live Feed) visuel
    print("🔥 Simulation de trafic entrant en direct (1 attaque toutes les 2 secondes).")
    print("👉 Vous pouvez ouvrir le Dashboard dans votre navigateur, vous le verrez bouger tout seul !")
    
    try:
        while True:
            conn = sqlite3.connect(DB_PATH)
            ev_type, severity, title, desc, raw = random.choice([
                ("SSH", "CRITICAL", "SSH Brute Force", "Live intrusion attempt on port 22.", "sshd: Failed password for invalid user bot "),
                ("FILE", "CRITICAL", "Suspicious File Access", "Malware trying to read config files.", "type=PATH msg=audit(): item=0 name=/etc/passwd "),
                ("SUDO", "WARNING", "Sudo Escalation", "Unknown binary executed with sudo.", "sudo: www-data : COMMAND=/usr/bin/wget ")
            ])
            unique_raw = raw + str(random.randint(100000, 999999))
            
            conn.execute('''
                INSERT INTO alerts (event_type, severity, title, description, raw_log)
                VALUES (?, ?, ?, ?, ?)
            ''', (ev_type, severity, title, desc, unique_raw))
            conn.commit()
            conn.close()
            
            print(f"    [+] Attaque {ev_type} insérée ! (Vérifiez le Dashboard)")
            time.sleep(4) # Une attaque toutes les 4s pour correspondre au setInterval(5000) de l'interface
            
    except KeyboardInterrupt:
        print("🛑 Simulation arrêtée.")
