FROM ubuntu:24.04
RUN apt-get update && apt-get install -y dnsutils && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /tmp/entrypoint.sh
RUN sed -i 's/\r$//' /tmp/entrypoint.sh && \
    chmod +x /tmp/entrypoint.sh
ENTRYPOINT ["/tmp/entrypoint.sh"]
