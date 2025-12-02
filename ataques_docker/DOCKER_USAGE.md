# Guia de Uso via Docker

Este guia mostra como construir e executar os ataques diretamente via Docker, usando o exemplo do **dos-http** que se aplica a todos os outros ataques.

## 📦 Exemplo: DoS HTTP Attack

### Passo 1: Construir a Imagem Docker

Navegue até a pasta do ataque e construa a imagem:

```bash
# Na raiz do projeto
cd dos-http

# Construir a imagem
docker build -t dos-http .
```

**Saída esperada:**
```
[+] Building image...
Sending build context to Docker daemon...
Step 1/5 : FROM ubuntu:24.04
...
Successfully built <image-id>
Successfully tagged dos-http:latest
```

### Passo 2: Executar o Ataque

Depois de construir a imagem, execute o container passando o IP da vítima:

**Opção 1 - IP como argumento (mais simples):**
```bash
docker run --rm --network host dos-http 192.168.137.141
```

**Opção 2 - IP via variável de ambiente:**
```bash
docker run --rm \
    --network host \
    -e TARGET_IP="192.168.137.141" \
    dos-http
```

**Ambas as formas funcionam!** A primeira é mais direta.

**Explicação dos parâmetros:**
- `--rm`: Remove o container automaticamente após execução
- `--network host`: Usa a rede do host (permite comunicação com outras máquinas na rede física)
- `192.168.137.141`: IP da vítima (passado como argumento)
- `dos-http`: Nome da imagem a ser executada

**Nota:** Você também pode usar variável de ambiente `-e TARGET_IP="..."` se preferir.

### Passo 3: Usando o Script (Método Recomendado)

O script `run.sh` automatiza tudo isso:

```bash
# Da pasta do ataque
./run.sh 192.168.137.141

# Ou da raiz do projeto
./run-dos-http.sh 192.168.137.141
```

O script automaticamente:
1. ✅ Verifica se a imagem existe
2. ✅ Constrói a imagem se necessário
3. ✅ Executa o ataque com os parâmetros corretos

---

## 🔄 Replicando para Outros Ataques

O mesmo processo funciona para **todos os outros ataques**. Apenas mude:
- Nome da pasta
- Nome da imagem Docker
- Parâmetros específicos (se houver)

### 1. Brute Force SSH

```bash
# Construir
cd brute-force-ssh
docker build -t brute-force-ssh .

# Executar (IP como argumento)
docker run --rm --network host brute-force-ssh 192.168.137.141

# Ou com variável de ambiente
docker run --rm --network host -e TARGET_IP="192.168.137.141" brute-force-ssh

# Ou usar o script
./run.sh 192.168.137.141
```

### 2. Ping Flood (ICMP)

**Nota:** Requer `--cap-add=NET_RAW` para usar hping3.

```bash
# Construir
cd ping-flood
docker build -t ping-flood .

# Executar (IP como argumento, com capability especial)
docker run --rm --network host --cap-add=NET_RAW ping-flood 192.168.137.141

# Ou com variável de ambiente
docker run --rm --network host --cap-add=NET_RAW -e TARGET_IP="192.168.137.141" ping-flood

# Ou usar o script
./run.sh 192.168.137.141
```

### 3. DNS Tunneling

```bash
# Construir
cd dns-tunneling
docker build -t dns-tunneling .

# Executar (não precisa de IP - envia queries para 8.8.8.8)
docker run --rm --network host dns-tunneling

# Ou usar o script
./run.sh
```

### 4. SQL Injection

```bash
# Construir
cd sql-injection
docker build -t sql-injection .

# Executar (IP como argumento - será convertido para http://IP)
docker run --rm --network host sql-injection 192.168.137.141

# Ou URL completa como argumento
docker run --rm --network host sql-injection http://192.168.137.141/login.php

# Ou com variável de ambiente
docker run --rm --network host -e TARGET_WEB="http://192.168.137.141" sql-injection

# Ou usar o script
./run.sh 192.168.137.141
# ou com porta customizada
./run.sh 192.168.137.141 8080
```

---

## 📋 Comandos Docker Úteis

### Listar Imagens Construídas

```bash
docker images | grep -E "dos-http|brute-force|ping-flood|dns-tunneling|sql-injection"
```

### Ver Logs de Execução

Os logs aparecem diretamente no terminal. Para salvar:

```bash
docker run --rm --network host -e TARGET_IP="192.168.137.141" dos-http > attack.log 2>&1
```

### Remover Imagens

```bash
# Remover uma imagem específica
docker rmi dos-http

# Remover todas as imagens de ataque
docker rmi dos-http brute-force-ssh ping-flood dns-tunneling sql-injection
```

### Verificar se a Imagem Existe

```bash
docker image inspect dos-http
```

---

## 🎯 Fluxo Completo de Trabalho

### Cenário: Testar Suricata em outra máquina

**Máquina Atacante (192.168.137.229):**
```bash
# 1. Ir para a pasta do ataque
cd dos-http

# 2. Executar o ataque (script faz build automático se necessário)
./run.sh 192.168.137.141
```

**Máquina com Suricata (192.168.137.141):**
```bash
# Monitorar logs em tempo real
tail -f ~/suricata-docker/logs/fast.log

# Ou verificar após o ataque
grep "192.168.137.229" ~/suricata-docker/logs/fast.log
```

---

## ⚠️ Troubleshooting

### Erro: "Cannot connect to Docker daemon"

```bash
# Verificar se Docker está rodando
docker ps

# No Linux, pode precisar de sudo
sudo docker build -t dos-http .
```

### Erro: "network host is not supported"

No Windows/Mac, `--network host` não funciona. Use bridge network:

```bash
# Para Windows/Mac
docker run --rm -e TARGET_IP="192.168.137.141" dos-http
```

**Nota:** Isso pode não funcionar se a vítima estiver em outra máquina. Considere usar WSL2 ou uma VM Linux.

### Imagem não encontrada

```bash
# Construir manualmente
cd dos-http
docker build -t dos-http .
```

### Container não consegue alcançar o alvo

```bash
# Testar conectividade primeiro
docker run --rm --network host alpine ping -c 3 192.168.137.141

# Se funcionar, o problema pode ser no entrypoint
```

---

## 🚀 Scripts vs Docker Direto

### Usar Script (Recomendado)
```bash
./dos-http/run.sh 192.168.137.141
```
✅ Automático (build se necessário)  
✅ Validações e testes  
✅ Mensagens informativas  

### Usar Docker Direto
```bash
cd dos-http
docker build -t dos-http .
docker run --rm --network host dos-http 192.168.137.141
```
✅ Controle total  
✅ Útil para debug  
✅ Automação em scripts próprios  

**Ambos funcionam!** Use o que preferir.

