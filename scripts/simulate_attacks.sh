#!/bin/bash



echo "[*] Démarrage de la simulation d'attaques..."

echo "[+] Scénario 1 : Usurpation via Sudo"
sudo -l &>/dev/null
sudo touch /root/test_sudo_usage.txt
echo "  -> Sudo exécuté."

echo "[+] Scénario 2 : Modification de fichiers sensibles (passwd)"
sudo touch /etc/passwd
sudo touch /etc/shadow
echo "  -> /etc/passwd et /etc/shadow accédés."

echo "[+] Scénario 3 : Changement de mot de passe"
sudo useradd hacker_test 2>/dev/null
echo "newpass" | sudo passwd --stdin hacker_test 2>/dev/null || echo -e "newpass\nnewpass" | sudo passwd hacker_test 2>/dev/null
echo "  -> Utilisateur hacker_test créé et mot de passe changé."

echo "[*] Simulation terminée ! Vérifiez votre application Python ou les logs."
