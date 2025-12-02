FROM python:3.9-alpine
RUN apk add --no-cache git sed \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap
WORKDIR /sqlmap
COPY entrypoint.sh /sqlmap/entrypoint.sh
RUN sed -i 's/\r$//' /sqlmap/entrypoint.sh && \
    chmod +x /sqlmap/entrypoint.sh
ENTRYPOINT ["/sqlmap/entrypoint.sh"]