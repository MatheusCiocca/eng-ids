#!/bin/bash

# Script para executar ataque DNS Tunneling
# Uso: ./run.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  DNS Tunneling Attack"
echo "=========================================="
echo ""
echo "Note: This attack sends DNS queries to 8.8.8.8"
echo "      The attack generates suspicious DNS traffic patterns"
echo ""

# Verifica se a imagem existe, se não, constrói
if ! docker image inspect dns-tunneling > /dev/null 2>&1; then
    echo "[+] Building dns-tunneling image..."
    docker build -t dns-tunneling .
    echo ""
fi

# Executa o ataque na rede do host (para comunicação com outras máquinas na rede)
echo "[+] Starting attack..."
docker run --rm \
    --network host \
    dns-tunneling

echo ""
echo "[+] Attack completed!"

