#!/bin/bash

# Script para executar ataque Brute Force SSH
# Uso: ./run.sh <TARGET_IP>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Verifica se o IP foi fornecido
if [ -z "$1" ]; then
    echo "Usage: $0 <TARGET_IP>"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo "  $0 172.18.0.2"
    exit 1
fi

TARGET_IP="$1"

# Valida formato básico de IP
if ! [[ $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[ERROR] Invalid IP format: $TARGET_IP"
    exit 1
fi

echo "=========================================="
echo "  SSH Brute Force Attack"
echo "=========================================="
echo ""
echo "Target: $TARGET_IP:22"
echo ""

# Verifica se a imagem existe, se não, constrói
if ! docker image inspect brute-force-ssh > /dev/null 2>&1; then
    echo "[+] Building brute-force-ssh image..."
    docker build -t brute-force-ssh .
    echo ""
fi

# Executa o ataque na rede do host (para comunicação com outras máquinas na rede)
echo "[+] Starting attack..."
docker run --rm \
    --network host \
    -e TARGET_IP="$TARGET_IP" \
    brute-force-ssh

echo ""
echo "[+] Attack completed!"

