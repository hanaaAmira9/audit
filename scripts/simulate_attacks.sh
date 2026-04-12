#!/bin/bash

# Script de Simulation d'Attaques Locales (VM1)
# Pour déclencher les alertes définies dans les règles auditd et monitor.

echo "[*] Démarrage de la simulation d'attaques..."



echo "[+] Scénario 1 : Usurpation via Sudo"
# Test d'accès root sans permission (si exécuté en user normal)
sudo -l &>/dev/null
# Ou accès root effectif
sudo touch /root/test_sudo_usage.txt
echo "  -> Sudo exécuté."

echo "[+] Scénario 2 : Modification de fichiers sensibles (passwd)"
# Touche les fichiers surveillés par auditd (-k identity)
sudo touch /etc/passwd
sudo touch /etc/shadow
echo "  -> /etc/passwd et /etc/shadow accédés."

echo "[+] Scénario 3 : Changement de mot de passe"
# Optionnel : changer le mot de passe d'un utilisateur de test (crée un user bidon)
sudo useradd hacker_test 2>/dev/null
echo "newpass" | sudo passwd --stdin hacker_test 2>/dev/null || echo -e "newpass\nnewpass" | sudo passwd hacker_test 2>/dev/null
echo "  -> Utilisateur hacker_test créé et mot de passe changé."

echo "[*] Simulation terminée ! Vérifiez votre application Python ou les logs."
