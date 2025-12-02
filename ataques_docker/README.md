# Containers Docker para Simulação de Ataques

Este diretório contém containers Docker para simular ataques de rede e um servidor alvo vulnerável para testes de IDS (Zeek, Snort, Suricata, etc.).

## 🚀 Início Rápido

### Modo Independente (Recomendado para testes gerais)

Os ataques funcionam **independentemente do SIMIR** e podem ser usados para testar qualquer IDS. Basta passar o IP da máquina alvo como parâmetro:

```bash
# Executar ataque individual passando IP da vítima
./run-dos-http.sh 192.168.1.100
./run-brute-force-ssh.sh 192.168.1.100
./run-ping-flood.sh 192.168.1.100
./run-sql-injection.sh 192.168.1.100
./run-dns-tunneling.sh
```

Ou use o menu interativo:

```bash
# Menu interativo com IP como parâmetro
./run-attack.sh 192.168.1.100
```

**Nota:** Os ataques usam `--network host` para se comunicar com máquinas na mesma rede física.

### Modo SIMIR (Compatibilidade)

Se você está usando o SIMIR com `./start-simir.sh` (Modo 2 - Rede Docker):

```bash
# Menu interativo (usa target.var automaticamente)
./run-attack.sh
```

---

## 📋 Componentes

### Servidor Alvo

**`target-server/`** - Servidor web vulnerável (Nginx + SSH)
- **IP fixo**: 172.18.0.2 (na rede Docker simir-net)
- **Portas**: 22 (SSH), 80 (HTTP)
- **Credenciais SSH**: root / toor
- **Uso**: Alvo para todos os ataques

**Gerenciamento:**
```bash
# Iniciar servidor alvo
./start-target.sh

# Parar servidor alvo
docker stop SIMIR_TARGET
```

### Containers de Ataque


| Container | Descrição | Script (Raiz) | Script (Pasta) |
|-----------|-----------|---------------|----------------|
| **dos-http** | HTTP Flood - 12.000+ requisições HTTP | `./run-dos-http.sh <IP>` | `./dos-http/run.sh <IP>` |
| **brute-force-ssh** | 100 tentativas de login SSH | `./run-brute-force-ssh.sh <IP>` | `./brute-force-ssh/run.sh <IP>` |
| **ping-flood** | ICMP Flood - 10s de pings contínuos | `./run-ping-flood.sh <IP>` | `./ping-flood/run.sh <IP>` |
| **dns-tunneling** | 200 queries DNS com dados exfiltrados | `./run-dns-tunneling.sh` | `./dns-tunneling/run.sh` |
| **sql-injection** | Exploits SQL injection com sqlmap | `./run-sql-injection.sh <IP> [PORT]` | `./sql-injection/run.sh <IP> [PORT]` |

**Nota:** Todos os ataques são independentes do SIMIR e podem ser usados para testar qualquer IDS (Zeek, Snort, Suricata, etc.).

**Organização:** Cada ataque tem seus arquivos organizados em sua própria pasta, incluindo o script de execução `run.sh`. Os scripts na raiz são wrappers que redirecionam para os scripts nas pastas.

---

## 🎯 Scripts Principais

### Scripts Individuais de Ataque

Cada ataque possui seu próprio script que aceita o IP da vítima como parâmetro:

#### `run-dos-http.sh` ou `dos-http/run.sh` - HTTP DoS/DDoS Attack

```bash
# Da raiz do projeto
./run-dos-http.sh <TARGET_IP>

# Ou da pasta do ataque
./dos-http/run.sh <TARGET_IP>
```

**Exemplo:**
```bash
./run-dos-http.sh 192.168.1.100
# ou
cd dos-http && ./run.sh 192.168.1.100
```

Gera ~12.000+ requisições HTTP usando múltiplas técnicas (Apache Bench, POST Flood, Slowloris, Header Flood).

#### `run-brute-force-ssh.sh` ou `brute-force-ssh/run.sh` - SSH Brute Force Attack

```bash
# Da raiz do projeto
./run-brute-force-ssh.sh <TARGET_IP>

# Ou da pasta do ataque
./brute-force-ssh/run.sh <TARGET_IP>
```

**Exemplo:**
```bash
./run-brute-force-ssh.sh 192.168.1.100
# ou
cd brute-force-ssh && ./run.sh 192.168.1.100
```

Executa 100 tentativas de login SSH com senhas aleatórias usando Hydra.

#### `run-ping-flood.sh` ou `ping-flood/run.sh` - ICMP Ping Flood

```bash
# Da raiz do projeto
./run-ping-flood.sh <TARGET_IP>

# Ou da pasta do ataque
./ping-flood/run.sh <TARGET_IP>
```

**Exemplo:**
```bash
./run-ping-flood.sh 192.168.1.100
# ou
cd ping-flood && ./run.sh 192.168.1.100
```

Gera inundação ICMP por 10 segundos com payloads de 1200 bytes (~900.000 pacotes).

#### `run-sql-injection.sh` ou `sql-injection/run.sh` - SQL Injection Attack

```bash
# Da raiz do projeto
./run-sql-injection.sh <TARGET_IP> [PORT]

# Ou da pasta do ataque
./sql-injection/run.sh <TARGET_IP> [PORT]
```

**Exemplos:**
```bash
./run-sql-injection.sh 192.168.1.100       # Porta 80 (padrão)
./run-sql-injection.sh 192.168.1.100 8080  # Porta 8080
./run-sql-injection.sh http://192.168.1.100/login.php  # URL completa
```

Executa sqlmap com nível 3 de testes contra o alvo.

#### `run-dns-tunneling.sh` ou `dns-tunneling/run.sh` - DNS Tunneling

```bash
# Da raiz do projeto
./run-dns-tunneling.sh

# Ou da pasta do ataque
./dns-tunneling/run.sh
```

**Nota:** Não requer IP (gera queries DNS para 8.8.8.8 com alta entropia).

Gera 200 queries DNS com subdomínios aleatórios de alta entropia (padrão de tunelamento).

### `run-attack.sh` - Menu Interativo de Ataques

Menu interativo para executar qualquer ataque:

```bash
# Com IP como parâmetro (modo independente)
./run-attack.sh 192.168.1.100

# Sem parâmetro (usa target.var - compatibilidade SIMIR)
./run-attack.sh
```

**Características:**
- ✅ Aceita IP como parâmetro para uso independente
- ✅ Compatível com SIMIR (usa target.var se não houver parâmetro)
- ✅ Detecta automaticamente rede correta (host ou simir-net)
- ✅ Interface amigável com descrições dos ataques

**Menu:**
```
==========================================
  Attack Simulation Menu
==========================================

Target Server: 192.168.1.100

Available Attacks:
  1) DoS HTTP         - HTTP Flood Attack
  2) Brute Force SSH  - SSH Login Attempts
  3) Ping Flood       - ICMP Flood
  4) DNS Tunneling    - DNS Exfiltration
  5) SQL Injection    - SQL Injection Attempts

  0) Exit

Select attack to run:
```

### `start-target.sh` - Iniciar Servidor Alvo

Inicia o servidor alvo na rede Docker:

```bash
./start-target.sh
```

**O que faz:**
- Verifica se a rede `simir-net` existe
- Inicia container `SIMIR_TARGET` com IP fixo 172.18.0.2
- Atualiza automaticamente o arquivo `target.var`
- Mostra status e instruções

### `build-images.sh` - Construir Imagens de Ataque

Constrói todas as imagens Docker dos ataques:

```bash
./build-images.sh
```

**Nota:** No modo Docker (usando `start-simir.sh`), as imagens são construídas automaticamente.

---

## 📝 Arquivo `target.var`

Contém as variáveis de ambiente com IPs dos alvos:

```bash
TARGET_HOST="172.18.0.2"    # IP do servidor alvo (SSH, ping)
TARGET_WEB="172.18.0.2"     # IP do servidor web (HTTP, SQL)
```

**Atualização Automática:**
- ✅ `start-simir.sh` (Modo 2) atualiza automaticamente
- ✅ `start-target.sh` atualiza ao iniciar o servidor

**Atualização Manual:**
```bash
echo 'TARGET_HOST="172.18.0.2"' > target.var
echo 'TARGET_WEB="172.18.0.2"' >> target.var
```

---

## 🔧 Uso Manual dos Containers

### Modo Independente (Recomendado)

Execute diretamente passando o IP da vítima via variável de ambiente:

```bash
# HTTP DoS (IP como argumento)
docker run --rm --network host dos-http 192.168.1.100
# ou com variável de ambiente
docker run --rm --network host -e TARGET_IP="192.168.1.100" dos-http

# SSH Brute Force (IP como argumento)
docker run --rm --network host brute-force-ssh 192.168.1.100
# ou com variável de ambiente
docker run --rm --network host -e TARGET_IP="192.168.1.100" brute-force-ssh

# ICMP Ping Flood (requer --cap-add=NET_RAW)
docker run --rm --network host --cap-add=NET_RAW ping-flood 192.168.1.100
# ou com variável de ambiente
docker run --rm --network host --cap-add=NET_RAW -e TARGET_IP="192.168.1.100" ping-flood

# SQL Injection (IP como argumento)
docker run --rm --network host sql-injection 192.168.1.100
# ou URL completa
docker run --rm --network host sql-injection http://192.168.1.100/login.php
# ou com variável de ambiente
docker run --rm --network host -e TARGET_WEB="http://192.168.1.100" sql-injection

# DNS Tunneling (não requer IP)
docker run --rm --network host dns-tunneling
```

### Modo SIMIR (Compatibilidade)

Se você está usando SIMIR com rede Docker:

```bash
# Com menu interativo
./run-attack.sh

# Ou diretamente na rede simir-net
docker run --rm --network simir-net -e TARGET_IP="172.18.0.2" dos-http
docker run --rm --network simir-net -e TARGET_IP="172.18.0.2" brute-force-ssh
docker run --rm --network simir-net --cap-add=NET_RAW -e TARGET_IP="172.18.0.2" ping-flood
docker run --rm --network simir-net -e TARGET_WEB="http://172.18.0.2" sql-injection
docker run --rm --network simir-net dns-tunneling
```

---

## 📖 Detalhes dos Ataques

### 1. DoS HTTP (`dos-http`)

**Descrição:** Ataque de negação de serviço HTTP com múltiplas técnicas

**O que faz:**
- Apache Bench: 10.000 requisições GET (200 conexões paralelas)
- POST Flood: 1.000 requisições POST maliciosas
- Slowloris: 200 conexões lentas (exaustão de recursos)
- Header Flood: 500 requisições com headers grandes (2KB)

**Total:** ~12.000+ conexões HTTP

**Detecção Esperada:**
- IDSs devem detectar padrões de DoS/DDoS
- Volume: >100 conexões de uma origem
- Tráfego HTTP anormalmente alto

**Exemplo (Zeek):**
```bash
docker exec SIMIR_Z grep 'DoS\|DDoS' /usr/local/zeek/spool/zeek/notice.log
```

---

### 2. Brute Force SSH (`brute-force-ssh`)

**Descrição:** Ataque de força bruta contra SSH

**O que faz:**
- Hydra: 100 tentativas de login SSH
- Usuário: root
- Alvo: ${TARGET_HOST}:22
- Senhas: Lista de senhas comuns

**Detecção Esperada:**
- IDSs devem detectar múltiplas tentativas de login SSH falhadas
- Padrão: >5 tentativas de autenticação falhadas da mesma origem

**Exemplo (Zeek):**
```bash
docker exec SIMIR_Z grep -i brute /usr/local/zeek/spool/zeek/notice.log
```

---

### 3. Ping Flood (`ping-flood`)

**Descrição:** Inundação ICMP para DoS

**O que faz:**
- 10 segundos de pings contínuos
- Sem intervalo entre pacotes
- Payload: 1200 bytes
- Alvo: ${TARGET_HOST}

**Volume:** ~900.000 pacotes ICMP

**Detecção Esperada:**
- IDSs devem detectar inundação ICMP
- Volume: >1000 pacotes/min de uma origem
- Tamanho anormal de payload (>1200 bytes)

**Exemplo (Zeek):**
```bash
docker exec SIMIR_Z grep 'ICMP' /usr/local/zeek/spool/zeek/notice.log
```

---

### 4. DNS Tunneling (`dns-tunneling`)

**Descrição:** Exfiltração de dados via DNS

**O que faz:**
- 200 queries DNS
- Subdomínios aleatórios com até 50 caracteres
- Simula túnel de dados
- Alta entropia nos nomes

**Detecção Esperada:**
- IDSs devem detectar padrões de tunelamento DNS
- Alta entropia nos subdomínios
- Subdomínios muito longos
- Volume anormal de queries DNS

**Exemplo (Zeek):**
```bash
docker exec SIMIR_Z grep 'DNS' /usr/local/zeek/spool/zeek/notice.log
```

---

### 5. SQL Injection (`sql-injection`)

**Descrição:** Exploits de injeção SQL

**O que faz:**
- Sqlmap contra ${TARGET_WEB}
- Testes de todas as vulnerabilidades
- Tentativas de dump de dados
- Bypass de autenticação

**Detecção Esperada:**
- IDSs devem detectar padrões SQL injection nas requisições HTTP
- Payloads SQL maliciosos (UNION, SELECT, DROP, etc.)
- Tentativas de bypass de autenticação

**Exemplo (Zeek):**
```bash
docker exec SIMIR_Z grep 'SQL' /usr/local/zeek/spool/zeek/notice.log
```

---

## 🏗️ Estrutura de Diretórios

```
ataques_docker/
├── README.md                          # Este arquivo
├── run-attack.sh                      # Menu interativo de ataques ⭐
├── run-dos-http.sh                    # Wrapper → dos-http/run.sh
├── run-brute-force-ssh.sh              # Wrapper → brute-force-ssh/run.sh
├── run-ping-flood.sh                  # Wrapper → ping-flood/run.sh
├── run-dns-tunneling.sh               # Wrapper → dns-tunneling/run.sh
├── run-sql-injection.sh               # Wrapper → sql-injection/run.sh
├── start-target.sh                    # Inicia servidor alvo ⭐
├── build-images.sh                    # Constrói todas as imagens
├── target.var                         # IPs dos alvos (atualizado automaticamente)
├── docker-compose-target-net.yml      # Config do servidor alvo
│
├── target-server/                     # Servidor alvo vulnerável ⭐
│   ├── Dockerfile                     # Nginx + OpenSSH
│   └── entrypoint.sh                  # Script de inicialização
│
├── dos-http/                          # DoS HTTP Attack
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── run.sh                         # Script de execução ⭐
│
├── brute-force-ssh/                   # SSH Brute Force Attack
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── run.sh                         # Script de execução ⭐
│
├── ping-flood/                        # ICMP Ping Flood Attack
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── run.sh                         # Script de execução ⭐
│
├── dns-tunneling/                     # DNS Tunneling Attack
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── run.sh                         # Script de execução ⭐
│
└── sql-injection/                     # SQL Injection Attack
    ├── Dockerfile
    ├── entrypoint.sh
    └── run.sh                         # Script de execução ⭐
```

---

## ⚠️ Visibilidade do Zeek

### Problema: Localhost → Localhost

**O Zeek NÃO vê tráfego localhost → localhost!**

Quando você executa ataques do próprio servidor SIMIR contra ele mesmo, o tráfego usa loopback e não passa pela interface que o Zeek monitora.

### Soluções

#### 1. Modo Docker (RECOMENDADO) ⭐

Use `start-simir.sh` e selecione **Modo 2 - Rede Docker**:
- ✅ Tudo na mesma máquina
- ✅ Zeek vê todo o tráfego
- ✅ Fácil de usar
- ✅ Isolado e seguro

```bash
cd /home/rafael/SIMIR
./start-simir.sh
# Escolha: 2 (Modo Rede Docker)

# Executar ataques
cd ataques_docker
./run-attack.sh
```

#### 2. Modo Interface Física

Use `start-simir.sh` e selecione **Modo 1 - Interface Física**:
- ⚠️ Requer **outra máquina** na rede para executar ataques
- ✅ Simula ambiente real
- ✅ Para produção

#### 3. Mais Informações

Veja documentação completa:
- [VISIBILITY_ISSUE.md](./VISIBILITY_ISSUE.md) - Explicação técnica
- [DOCKER_MONITORING_GUIDE.md](./DOCKER_MONITORING_GUIDE.md) - Guia completo
- [DOCKER_NETWORK_ARCHITECTURE.md](./DOCKER_NETWORK_ARCHITECTURE.md) - Arquitetura

---

## 🔍 Monitoramento de Detecções

### Ver Alertas em Tempo Real

```bash
docker exec SIMIR_Z tail -f /usr/local/zeek/spool/zeek/notice.log
```

### Buscar Alertas Específicos

```bash
# DoS/DDoS
docker exec SIMIR_Z grep 'DoS\|DDoS' /usr/local/zeek/spool/zeek/notice.log

# Brute Force
docker exec SIMIR_Z grep -i brute /usr/local/zeek/spool/zeek/notice.log

# DNS Tunneling
docker exec SIMIR_Z grep 'DNS' /usr/local/zeek/spool/zeek/notice.log

# SQL Injection
docker exec SIMIR_Z grep 'SQL' /usr/local/zeek/spool/zeek/notice.log

# ICMP Flood
docker exec SIMIR_Z grep 'ICMP' /usr/local/zeek/spool/zeek/notice.log
```

### Estatísticas

```bash
# Contar alertas por tipo
docker exec SIMIR_Z cat /usr/local/zeek/spool/zeek/notice.log | \
  grep -v '^#' | awk '{print $11}' | sort | uniq -c

# Total de alertas
docker exec SIMIR_Z grep -v '^#' /usr/local/zeek/spool/zeek/notice.log | wc -l
```

---

## 🆘 Troubleshooting

### Ataque não detectado

**Verifique o modo:**
```bash
# Está no modo Docker?
docker network ls | grep simir-net

# Servidor alvo está rodando?
docker ps | grep SIMIR_TARGET

# Zeek está rodando?
docker exec SIMIR_Z zeekctl status
```

### Servidor alvo não responde

```bash
# Reiniciar servidor alvo
docker stop SIMIR_TARGET
./start-target.sh

# Verificar conectividade
docker run --rm --network simir-net alpine ping -c 3 172.18.0.2
```

### Containers não encontram target

```bash
# Verificar target.var
cat target.var

# Atualizar manualmente
echo 'TARGET_HOST="172.18.0.2"' > target.var
echo 'TARGET_WEB="172.18.0.2"' >> target.var

# Reconstruir imagens
./build-images.sh
```

---

## 📚 Documentação Adicional

- **[VISIBILITY_ISSUE.md](./VISIBILITY_ISSUE.md)** - Por que localhost não funciona
- **[DOCKER_MONITORING_GUIDE.md](./DOCKER_MONITORING_GUIDE.md)** - Guia completo do modo Docker
- **[DOCKER_NETWORK_ARCHITECTURE.md](./DOCKER_NETWORK_ARCHITECTURE.md)** - Arquitetura técnica
- **[../START_GUIDE.md](../START_GUIDE.md)** - Guia de início do SIMIR
- **[../docs/MANUAL_COMPLETO.md](../docs/MANUAL_COMPLETO.md)** - Manual completo

---

## ⚖️ Aviso Legal

**USO APENAS EM AMBIENTES DE TESTE!**

Estes ataques são para **fins educacionais e de teste** em ambientes controlados. O uso em sistemas sem autorização é **ilegal** e pode resultar em consequências criminais.

- ✅ Use apenas em redes de teste
- ✅ Obtenha autorização por escrito
- ✅ Documente todos os testes
- ❌ Nunca use em produção sem permissão
- ❌ Nunca ataque sistemas de terceiros
