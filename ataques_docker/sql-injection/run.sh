#!/bin/bash

# Script para executar ataque SQL Injection
# Uso: ./run.sh <TARGET_IP> [PORT]
# PORT é opcional, padrão é 80

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Verifica se o IP foi fornecido
if [ -z "$1" ]; then
    echo "Usage: $0 <TARGET_IP> [PORT]"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo "  $0 192.168.1.100 8080"
    echo "  $0 http://192.168.1.100/login.php"
    exit 1
fi

TARGET="$1"
PORT="${2:-80}"

# Se o target já contém http://, usa como está
if [[ $TARGET == http://* ]] || [[ $TARGET == https://* ]]; then
    TARGET_WEB="$TARGET"
else
    # Valida formato básico de IP
    if ! [[ $TARGET =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "[ERROR] Invalid IP format: $TARGET"
        exit 1
    fi
    
    TARGET_WEB="http://${TARGET}:${PORT}"
fi

echo "=========================================="
echo "  SQL Injection Attack"
echo "=========================================="
echo ""
echo "Target: $TARGET_WEB"
echo ""

# Verifica se a imagem existe, se não, constrói
if ! docker image inspect sql-injection > /dev/null 2>&1; then
    echo "[+] Building sql-injection image..."
    docker build -t sql-injection .
    echo ""
fi

# Executa o ataque na rede do host (para comunicação com outras máquinas na rede)
echo "[+] Starting attack..."
docker run --rm \
    --network host \
    -e TARGET_WEB="$TARGET_WEB" \
    -e TARGET_IP="${TARGET_WEB#http://}" \
    sql-injection

echo ""
echo "[+] Attack completed!"

