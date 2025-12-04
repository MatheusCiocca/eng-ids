#!/bin/bash

##############################################
# BENCHMARK PARA IDS - CPU, RAM, LATÊNCIA
# Vários ataques em sequência
##############################################

LOG_FILE="home/zeek/eng-ids/zeek-docker/logs/notice.log" # ajustar conforme caminho do log do IDS
OUTPUT_DIR="benchmark_results"
INTERVAL=0.5
ATTACK_NUM=1

mkdir -p "$OUTPUT_DIR"

# Função para obter uso de CPU (%)
get_cpu() {
    mpstat 1 1 | awk '/Average:/ {print 100 - $12}'
}

# Função para obter uso de RAM (MB)
get_ram() {
    free -m | awk '/Mem:/ {print $3}'
}

echo "==============================================="
echo " BENCHMARK – ENTER 'new' para iniciar ataque "
echo "==============================================="
echo ""
echo "Aguardando comando 'new'..."
echo ""

# Estado interno
monitoring=0
start_time=0
log_initial_size=0
latency_measured=0
peak_cpu=0
peak_ram=0


while true; do
    
    # -----------------------------
    # ESPERAR "new" PARA INICIAR ATAQUE
    # -----------------------------
    if [ $monitoring -eq 0 ]; then
        read -t 0.2 cmd
        if [ "$cmd" == "new" ]; then
            echo ""
            echo ">>> NOVO ATAQUE REGISTRADO"
            echo ""

            # Reset de estado
            peak_cpu=0
            peak_ram=0
            latency_measured=0

            # Guardar estado inicial do log
            if [ ! -f "$LOG_FILE" ]; then
                echo "ERRO: Log não encontrado: $LOG_FILE"
                exit 1
            fi

            log_initial_size=$(wc -c < "$LOG_FILE")
            start_time=$(date +%s)

            monitoring=1

            echo "[OK] Ataque $ATTACK_NUM iniciado. Monitorando CPU, RAM e latência."
            echo ""
        fi
        continue
    fi

    # ---------------------------------------------------
    # MONITORA CPU E RAM
    # ---------------------------------------------------
    current_cpu=$(get_cpu)
    current_ram=$(get_ram)

    if (( $(echo "$current_cpu > $peak_cpu" | bc -l) )); then
        peak_cpu=$current_cpu
    fi

    if (( $(echo "$current_ram > $peak_ram" | bc -l) )); then
        peak_ram=$current_ram
    fi


    # ---------------------------------------------------
    # DETECÇÃO DE LATÊNCIA (mudança no log)
    # ---------------------------------------------------
    if [ $latency_measured -eq 0 ]; then
        new_size=$(wc -c < "$LOG_FILE")

        if [ "$new_size" -gt "$log_initial_size" ]; then
            latency_measured=1
            end_time=$(date +%s)
            latency=$(( end_time - start_time ))

            echo ">>> DETECTADO PRIMEIRO LOG! LATÊNCIA = ${latency}s"
        fi
    fi


    # ---------------------------------------------------
    # FINALIZAÇÃO DO ATAQUE
    # Após detectar a latência, espera o usuário digitar "new"
    # ---------------------------------------------------
    if [ $latency_measured -eq 1 ]; then

        read -t 0.2 cmd

        if [ "$cmd" == "new" ]; then
            # Salvar resultado do ataque
            OUTPUT_FILE="$OUTPUT_DIR/attack_$(printf "%02d" $ATTACK_NUM).txt"

            {
                echo "============================="
                echo "     RESULTADO DO ATAQUE $ATTACK_NUM"
                echo "============================="
                echo "Latência: ${latency}s"
                echo "Pico CPU: ${peak_cpu}%"
                echo "Pico RAM: ${peak_ram} MB"
                echo "Log inicial: $log_initial_size bytes"
                echo ""
                echo "Início: $(date -d @$start_time '+%H:%M:%S')"
                echo "Detecção: $(date -d @$end_time '+%H:%M:%S')"
            } > "$OUTPUT_FILE"

            echo ""
            echo "[SALVO] -> $OUTPUT_FILE"
            echo ""

            ATTACK_NUM=$((ATTACK_NUM + 1))
            monitoring=0

            echo "Pronto para próximo ataque. Digite 'new'."
            echo ""
        fi
    fi

    sleep $INTERVAL
done
