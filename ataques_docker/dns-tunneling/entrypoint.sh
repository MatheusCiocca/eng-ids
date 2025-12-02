#!/usr/bin/env bash

# Define o alvo. Se passar argumento usa ele, senão tenta o Gateway padrão
TARGET_DNS="$1"

if [ -z "$TARGET_DNS" ]; then
    echo "[!] Erro: Você precisa especificar o IP do alvo (PC do Suricata)"
    echo "Uso: docker run ... dns-tunneling <IP_DO_SURICATA>"
    exit 1
fi

echo "[+] Iniciando Ataque DNS Tunneling"
echo "[+] Alvo: $TARGET_DNS"
echo "[+] Gerando queries com alta entropia..."

function DNS() {
  RANGE=$(( 12 + $RANDOM % 50 ))
  DOMAIN=$( cat /dev/urandom | tr -dc "0-9a-fA-F" | fold -w "${RANGE}" | head -n 1 )
  
  # AQUI ESTÁ O SEGREDO: @$TARGET_DNS
  # Removemos o sleep para garantir volume para a Regra 15
  dig @$TARGET_DNS +time=1 +tries=1 +short "${DOMAIN}.com" > /dev/null 2>&1
}

# Loop de ataque (Aumentei a velocidade removendo o sleep e rodando em background controlado)
for i in $( seq 1 200 ); do
  DNS &
  # Pequena pausa apenas a cada 10 requests para não travar o Docker no Windows
  if (( $i % 10 == 0 )); then sleep 0.1; fi
done

wait
echo "[+] Ataque finalizado contra $TARGET_DNS"