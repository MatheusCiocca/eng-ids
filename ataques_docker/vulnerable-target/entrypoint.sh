#!/bin/bash
set -e

echo "[+] Starting vulnerable web + database server..."
service mariadb start

# Espera o MySQL inicializar
sleep 5

echo "[+] Initializing database..."
mysql -u root -e "CREATE DATABASE IF NOT EXISTS vulnerable;"
mysql -u root vulnerable < /docker-entrypoint-initdb.d/init.sql

echo "[+] Database initialized."
echo "[+] Starting Apache web server..."
apache2-foreground
