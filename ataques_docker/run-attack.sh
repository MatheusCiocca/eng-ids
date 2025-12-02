#!/bin/bash

# Script para executar ataques simulados
# Uso: ./run-attack.sh [TARGET_IP]
# Se TARGET_IP não for fornecido, tenta usar target.var (compatibilidade com SIMIR)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Verifica se IP foi passado como parâmetro
if [ -n "$1" ]; then
    TARGET_IP="$1"
    # Valida formato básico de IP
    if ! [[ $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "[ERROR] Invalid IP format: $TARGET_IP"
        exit 1
    fi
    USE_PARAM_IP=true
else
    # Modo compatibilidade: tenta usar target.var
    if [ -f "target.var" ]; then
        source target.var
        TARGET_IP=$(echo "$TARGET_WEB" | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d'/' -f1 | cut -d':' -f1)
        USE_PARAM_IP=false
    else
        echo "[ERROR] No TARGET_IP provided and target.var not found"
        echo "Usage: $0 [TARGET_IP]"
        echo "Example: $0 192.168.1.100"
        exit 1
    fi
fi

# Função para exibir menu
show_menu() {
    echo ""
    echo "=========================================="
    echo "  Attack Simulation Menu"
    echo "=========================================="
    echo ""
    if [ "$USE_PARAM_IP" = true ]; then
        echo "Target Server: $TARGET_IP"
    else
        echo "Target Server: $TARGET_IP (from target.var)"
    fi
    echo ""
    echo "Available Attacks:"
    echo "  1) DoS HTTP         - HTTP Flood Attack"
    echo "  2) Brute Force SSH  - SSH Login Attempts"
    echo "  3) Ping Flood       - ICMP Flood"
    echo "  4) DNS Tunneling    - DNS Exfiltration"
    echo "  5) SQL Injection    - SQL Injection Attempts"
    echo ""
    echo "  0) Exit"
    echo ""
    read -p "Select attack to run: " choice
}

# Função para executar ataque
run_attack() {
    local attack=$1
    local image=$2
    local env_var=""
    
    echo ""
    echo "[+] Starting $attack attack..."
    
    # Determina variável de ambiente baseada no tipo de ataque
    case "$image" in
        dos-http)
            env_var="TARGET_IP"
            ;;
        sql-injection)
            env_var="TARGET_WEB"
            env_value="http://${TARGET_IP}"
            ;;
        brute-force-ssh|ping-flood)
            env_var="TARGET_IP"
            ;;
        dns-tunneling)
            # DNS tunneling não precisa de IP (usa 8.8.8.8)
            env_var=""
            ;;
    esac
    
    # Determina rede: se IP foi passado como parâmetro, usa host network
    # Caso contrário, tenta usar simir-net se existir (compatibilidade)
    if [ "$USE_PARAM_IP" = true ]; then
        NETWORK="host"
        echo "[+] Running on host network (target: $TARGET_IP)"
    elif docker network ls | grep -q simir-net; then
        NETWORK="simir-net"
        echo "[+] Running on simir-net (Docker mode, target: $TARGET_IP)"
    else
        NETWORK="host"
        echo "[+] Running on host network (target: $TARGET_IP)"
    fi
    
    echo ""
    
    # Executa com as opções apropriadas
    if [ "$image" = "ping-flood" ]; then
        # ping-flood precisa de NET_RAW capability
        docker run --rm --network "$NETWORK" --cap-add=NET_RAW ${env_var:+-e "$env_var=$TARGET_IP"} "$image"
    elif [ -n "$env_var" ]; then
        # SQL Injection usa TARGET_WEB, outros usam TARGET_IP
        if [ "$env_var" = "TARGET_WEB" ]; then
            docker run --rm --network "$NETWORK" -e "$env_var=$env_value" "$image"
        else
            docker run --rm --network "$NETWORK" -e "$env_var=$TARGET_IP" "$image"
        fi
    else
        docker run --rm --network "$NETWORK" "$image"
    fi
    
    echo ""
    echo "[+] Attack completed!"
    
    if [ "$USE_PARAM_IP" = false ] && docker ps | grep -q SIMIR_Z; then
        echo "[+] Check Zeek logs (if using SIMIR):"
        echo "    docker exec SIMIR_Z tail -20 /usr/local/zeek/spool/zeek/notice.log"
    else
        echo "[+] Check your IDS logs for detections"
    fi
    echo ""
    
    read -p "Press Enter to continue..."
}

# Loop principal
while true; do
    show_menu
    
    case $choice in
        1)
            run_attack "DoS HTTP" "dos-http"
            ;;
        2)
            run_attack "Brute Force SSH" "brute-force-ssh"
            ;;
        3)
            run_attack "Ping Flood" "ping-flood"
            ;;
        4)
            run_attack "DNS Tunneling" "dns-tunneling"
            ;;
        5)
            run_attack "SQL Injection" "sql-injection"
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "[ERROR] Invalid option"
            sleep 2
            ;;
    esac
done
