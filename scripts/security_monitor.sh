#!/bin/bash

AUTH_LOG="/var/log/auth.log"
ALERT_LOG="/var/log/security_alerts.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

echo "===== Analyse de sécurité : $DATE =====" >> "$ALERT_LOG"

# 1. Détection des échecs de connexion SSH
FAILED_SSH=$(grep "Failed password" "$AUTH_LOG" | tail -n 20)
if [ ! -z "$FAILED_SSH" ]; then
    echo "[ALERTE] Tentatives SSH échouées détectées :" >> "$ALERT_LOG"
    echo "$FAILED_SSH" >> "$ALERT_LOG"
fi

# 2. Détection des connexions root
ROOT_LOGIN=$(grep "session opened for user root" "$AUTH_LOG" | tail -n 10)
if [ ! -z "$ROOT_LOGIN" ]; then
    echo "[ALERTE] Ouverture de session root :" >> "$ALERT_LOG"
    echo "$ROOT_LOGIN" >> "$ALERT_LOG"
fi

# 3. Détection usage sudo
SUDO_USAGE=$(grep "sudo:" "$AUTH_LOG" | tail -n 20)
if [ ! -z "$SUDO_USAGE" ]; then
    echo "[INFO] Utilisation de sudo :" >> "$ALERT_LOG"
    echo "$SUDO_USAGE" >> "$ALERT_LOG"
fi

# 4. Détection ajout utilisateur
USER_ADD=$(grep "useradd" "$AUTH_LOG" | tail -n 10)
if [ ! -z "$USER_ADD" ]; then
    echo "[ALERTE] Création de compte détectée :" >> "$ALERT_LOG"
    echo "$USER_ADD" >> "$ALERT_LOG"
fi

echo "" >> "$ALERT_LOG"
