# Problema de Line Endings (CRLF vs LF)

## 🔴 Erro Comum

```
/usr/bin/env: 'bash\r': No such file or directory
```

## 📋 Causa

Windows usa **CRLF** (`\r\n`) como fim de linha, mas Linux/Docker espera apenas **LF** (`\n`). Quando você edita arquivos `.sh` no Windows, eles ficam com `\r` no final, causando esse erro.

## ✅ Solução Implementada

Adicionei `sed -i 's/\r$//'` em todos os Dockerfiles para remover automaticamente os `\r` durante o build:

```dockerfile
COPY entrypoint.sh /tmp/entrypoint.sh
RUN sed -i 's/\r$//' /tmp/entrypoint.sh && \
    chmod +x /tmp/entrypoint.sh
```

Isso garante que mesmo arquivos editados no Windows funcionem corretamente no Docker.

## 🔧 Rebuild Necessário

Depois dessa correção, você precisa **rebuild** todas as imagens:

```bash
cd dos-http
docker build -t dos-http .

cd ../brute-force-ssh
docker build -t brute-force-ssh .

cd ../ping-flood
docker build -t ping-flood .

cd ../dns-tunneling
docker build -t dns-tunneling .

cd ../sql-injection
docker build -t sql-injection .
```

## 💡 Prevenção Futura

### Opção 1: Configurar Git (Recomendado)

```bash
# Converter automaticamente ao commitar
git config --global core.autocrlf input

# Ou para Windows especificamente
git config --global core.autocrlf true
```

### Opção 2: Usar Editor com LF

Configure seu editor (VS Code, etc.) para usar LF ao invés de CRLF:
- VS Code: Bottom right → Click "CRLF" → Select "LF"
- Ou adicione no `.editorconfig`:
```ini
[*]
end_of_line = lf
```

### Opção 3: Script de Limpeza

Se precisar limpar manualmente:
```bash
# No Linux/WSL/Git Bash
dos2unix entrypoint.sh

# Ou com sed
sed -i 's/\r$//' entrypoint.sh
```

## ✅ Agora Deve Funcionar

Após rebuild, todos os containers devem funcionar corretamente:

```bash
docker run --rm --network host dos-http 192.168.137.141
docker run --rm --network host brute-force-ssh 192.168.137.141
docker run --rm --network host --cap-add=NET_RAW ping-flood 192.168.137.141
docker run --rm --network host sql-injection 192.168.137.141
docker run --rm --network host dns-tunneling
```

