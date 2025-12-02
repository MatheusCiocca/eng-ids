#!/bin/bash

# Wrapper script - redireciona para o script dentro da pasta do ataque
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/brute-force-ssh/run.sh" "$@"

