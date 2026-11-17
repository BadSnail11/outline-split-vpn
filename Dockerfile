FROM python:3.12-slim-bookworm

ARG SINGBOX_VERSION=1.12.20

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 nftables \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac \
    && curl -fsSL -o /tmp/sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${arch}.tar.gz" \
    && tar -xzf /tmp/sing-box.tar.gz -C /tmp \
    && install -m 0755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${arch}/sing-box" /usr/local/bin/sing-box \
    && rm -rf /tmp/sing-box.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${arch}" \
    && apt-get purge -y curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/outline-split
COPY app ./app

ENV PYTHONUNBUFFERED=1 \
    OUTLINE_DATA=/data \
    SINGBOX_BIN=/usr/local/bin/sing-box

VOLUME ["/data"]
EXPOSE 8787

CMD ["python", "-m", "app"]
