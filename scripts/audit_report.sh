#!/bin/bash

REPORT="audit_summary.txt"

echo "===== Rapport auditd =====" > "$REPORT"
echo "Date: $(date)" >> "$REPORT"
echo "" >> "$REPORT"

echo "1. Modifications de fichiers sensibles" >> "$REPORT"
ausearch -k identity >> "$REPORT"
echo "" >> "$REPORT"

echo "2. Élévation de privilèges" >> "$REPORT"
ausearch -k priv_esc >> "$REPORT"
echo "" >> "$REPORT"

echo "3. Changement de mot de passe" >> "$REPORT"
ausearch -k passwd_change >> "$REPORT"
echo "" >> "$REPORT"

echo "4. Exécutions de commandes" >> "$REPORT"
ausearch -k command_exec >> "$REPORT"
echo "" >> "$REPORT"

echo "Rapport généré dans $REPORT"
