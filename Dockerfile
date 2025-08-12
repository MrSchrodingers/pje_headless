# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

# Dependências de runtime mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Diretórios
WORKDIR /app
RUN adduser --disabled-password --gecos "" --home /app app && chown -R app:app /app

# Copia projeto
COPY pyproject.toml README.md /app/
COPY pjeoffice_headless.py /app/

# Instala dependências
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir .

# Labels OCI
LABEL org.opencontainers.image.title="pjeoffice-headless" \
      org.opencontainers.image.description="Autenticador headless PJe Office (CNJ) que assina desafios via certificado A1 (PKCS#12)" \
      org.opencontainers.image.licenses="GNU General Public License v3.0" \
      org.opencontainers.image.version="1.0.0"

# Entrypoint (env -> flags)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8800
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:${PJE_PORT:-8800}/pjeOffice/ || exit 1

USER app
ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
