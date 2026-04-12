# Simulateur d'Attaques pour Windows Host (Génération de logs compatibles)
# Ce script crée ou ajoute de fausses lignes à 'windows_security.log' au même endroit que 'app.py' l'attend.

$LogFile = "windows_security.log"

Write-Host "[*] Démarrage de la simulation d'attaques sur Windows..." -ForegroundColor Cyan

# Création du fichier s'il n'existe pas
if (-Not (Test-Path $LogFile)) {
    New-Item -ItemType File -Path $LogFile | Out-Null
}

Write-Host "[+] Scénario 1 : Simulation de Bruteforce SSH (Échecs de connexion RDP/Local simulés)" -ForegroundColor Yellow
$timestamp = Get-Date -Format "MMM dd HH:mm:ss"
"$timestamp windows-host sshd[1234]: Failed password for fakeuser from 192.168.56.20 port 54321 ssh2" | Out-File -FilePath $LogFile -Append -Encoding utf8
"$timestamp windows-host sshd[1234]: Failed password for fakeuser from 192.168.56.20 port 54321 ssh2" | Out-File -FilePath $LogFile -Append -Encoding utf8
"$timestamp windows-host sshd[1234]: Failed password for fakeuser from 192.168.56.20 port 54321 ssh2" | Out-File -FilePath $LogFile -Append -Encoding utf8
Start-Sleep -Seconds 1
Write-Host "  -> Faux logs d'échecs brutes force injectés." -ForegroundColor Green

Write-Host "[+] Scénario 2 : Usurpation Administrateur (Root Login)" -ForegroundColor Yellow
$timestamp = Get-Date -Format "MMM dd HH:mm:ss"
"$timestamp windows-host su: pam_unix(su:session): session opened for user root by admin(uid=0)" | Out-File -FilePath $LogFile -Append -Encoding utf8
Start-Sleep -Seconds 1
Write-Host "  -> Faux login administrateur déclenché." -ForegroundColor Green

Write-Host "[+] Scénario 3 : Exécution de commandes privilégiées (Sudo)" -ForegroundColor Yellow
$timestamp = Get-Date -Format "MMM dd HH:mm:ss"
"$timestamp windows-host sudo:  hacker : TTY=pts/1 ; PWD=/home/hacker ; USER=root ; COMMAND=/usr/bin/bash" | Out-File -FilePath $LogFile -Append -Encoding utf8
Start-Sleep -Seconds 1
Write-Host "  -> Fausse élévation de privilèges (UAC/Sudo) déclenchée." -ForegroundColor Green

Write-Host "[+] Scénario 4 : Accès aux fichiers sensibles (Simule auditd)" -ForegroundColor Yellow
$timestamp = Get-Date -Format "MMM dd HH:mm:ss"
"type=PATH msg=audit(161000.123:45): item=0 name=/etc/passwd inode=123 dev=sda1 mode=file,644 ouid=0 ogid=0 rdev=00:00" | Out-File -FilePath $LogFile -Append -Encoding utf8
Start-Sleep -Seconds 1
Write-Host "  -> Fausse modification de fichier sensible enregistrée." -ForegroundColor Green


Write-Host "`n[*] Simulation terminée ! Regardez votre Dashboard s'actualiser avec de nouveaux événements." -ForegroundColor Cyan
Start-Sleep -Seconds 3
