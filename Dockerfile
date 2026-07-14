# ===== 阶段 1：构建 Vue 前端 =====
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build
# 产物在 /fe/../web/dist → /web/dist

# ===== 阶段 2：Python 应用 + 全套安全工具 =====
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 系统工具 + 挖洞常用工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap \
        python3-pip \
        jq dnsutils iputils-ping netcat-openbsd \
        whatweb unzip \
    && rm -rf /var/lib/apt/lists/*

# sqlmap（git 安装，复用官方）
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# Python's httpx package installs an httpx console script. Install Python
# dependencies first so the ProjectDiscovery binary below is the final one.
WORKDIR /app
COPY requirements.txt requirements-tools.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-tools.txt

# SRC 二进制工具：固定官方 release 并校验 SHA256；TARGETARCH 由 buildkit 注入。
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported TARGETARCH=$TARGETARCH"; exit 1 ;; esac; \
    NUCLEI_VER=3.11.0; HTTPX_VER=1.10.0; KATANA_VER=1.6.1; \
    FFUF_VER=2.2.1; DALFOX_VER=3.1.2; \
    case "$TARGETARCH" in amd64) DALFOX_ARCH=x86_64 ;; arm64) DALFOX_ARCH=aarch64 ;; esac; \
    cd /tmp; \
    NUCLEI_ASSET="nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip"; \
    HTTPX_ASSET="httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip"; \
    KATANA_ASSET="katana_${KATANA_VER}_linux_${TARGETARCH}.zip"; \
    FFUF_ASSET="ffuf_${FFUF_VER}_linux_${TARGETARCH}.tar.gz"; \
    DALFOX_ASSET="dalfox-v${DALFOX_VER}-linux-${DALFOX_ARCH}-musl.tar.gz"; \
    DALFOX_DIR="dalfox-v${DALFOX_VER}-linux-${DALFOX_ARCH}-musl"; \
    download() { curl --fail --silent --show-error --location --retry 4 --retry-delay 2 --retry-all-errors "$1" -o "$2"; }; \
    download "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/${NUCLEI_ASSET}" "$NUCLEI_ASSET"; \
    download "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_checksums.txt" nuclei-checksums.txt; \
    download "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/${HTTPX_ASSET}" "$HTTPX_ASSET"; \
    download "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_checksums.txt" httpx-checksums.txt; \
    download "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/${KATANA_ASSET}" "$KATANA_ASSET"; \
    download "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/katana-${KATANA_VER}-checksums.txt" katana-checksums.txt; \
    download "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/${FFUF_ASSET}" "$FFUF_ASSET"; \
    download "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_checksums.txt" ffuf-checksums.txt; \
    download "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/${DALFOX_ASSET}" "$DALFOX_ASSET"; \
    download "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/${DALFOX_ASSET}.sha256" dalfox-checksums.txt; \
    for pair in \
      "nuclei-checksums.txt:${NUCLEI_ASSET}" \
      "httpx-checksums.txt:${HTTPX_ASSET}" \
      "katana-checksums.txt:${KATANA_ASSET}" \
      "ffuf-checksums.txt:${FFUF_ASSET}" \
      "dalfox-checksums.txt:${DALFOX_ASSET}"; do \
        sums="${pair%%:*}"; asset="${pair#*:}"; \
        line="$(tr -d '\r' < "$sums" | awk -v asset="$asset" 'NF >= 2 { name=$2; sub(/^\*/, "", name); if (name == asset) print }')"; \
        test -n "$line"; \
        test "$(printf '%s\n' "$line" | wc -l)" -eq 1; \
        printf '%s\n' "$line" | sha256sum -c -; \
    done; \
    unzip -oq "$NUCLEI_ASSET" nuclei -d /usr/local/bin/; \
    unzip -oq "$HTTPX_ASSET" httpx -d /usr/local/bin/; \
    unzip -oq "$KATANA_ASSET" katana -d /usr/local/bin/; \
    tar -xzf "$FFUF_ASSET" -C /usr/local/bin/ ffuf; \
    tar -xzf "$DALFOX_ASSET" --strip-components=1 -C /usr/local/bin/ "$DALFOX_DIR/dalfox"; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx /usr/local/bin/katana \
      /usr/local/bin/ffuf /usr/local/bin/dalfox; \
    rm -f /tmp/*.zip /tmp/*.tar.gz /tmp/*-checksums.txt

RUN httpx -version \
    && katana -version \
    && nuclei -version \
    && ffuf -V \
    && dalfox --version

# 更新 nuclei 模板（失败不阻断构建）
RUN nuclei -update-templates -silent || true

COPY . .

# 拷入前端构建产物（覆盖空的 web/dist）
COPY --from=frontend /web/dist /app/web/dist

# 工作区 + 数据目录（数据目录建议挂卷持久化）
RUN mkdir -p /work /app/data
ENV WORKER_WORK_ROOT=/work \
    DB_PATH=/app/data/autohunter.db

EXPOSE 18800

CMD ["sh", "/app/scripts/run-with-watchdog.sh"]
