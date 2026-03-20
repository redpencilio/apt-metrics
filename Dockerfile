FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apt \
        curl \
        jq \
        lsb-release \
    && rm -rf /var/lib/apt/lists/*

COPY security-updates-metrics.sh /usr/local/bin/security-updates-metrics.sh
RUN chmod +x /usr/local/bin/security-updates-metrics.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
