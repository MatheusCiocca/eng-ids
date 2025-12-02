FROM php:8.2-apache

# Instala o cliente e servidor MySQL no mesmo container (para ambiente isolado)
RUN apt-get update && \
    apt-get install -y mariadb-server && \
    docker-php-ext-install mysqli && \
    rm -rf /var/lib/apt/lists/*

# Copia os arquivos da aplicação web
COPY www/ /var/www/html/
COPY init.sql /docker-entrypoint-initdb.d/init.sql
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]