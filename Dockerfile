# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Stage 1: build
# CGO e necessario para miekg/pkcs11 (binding C do PKCS#11).
# ---------------------------------------------------------------------------
FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copiar modulos primeiro para aproveitar o cache de layers.
COPY go.mod go.sum ./
RUN go mod download

# Copiar o restante do codigo-fonte.
COPY cmd/       cmd/
COPY internal/  internal/

RUN CGO_ENABLED=1 go build -trimpath -o /out/pjeheadless ./cmd/pjeheadless

# ---------------------------------------------------------------------------
# Stage 2: runtime
# Imagem slim; apenas o binario e as dependencias de sistema necessarias.
#
# Modo token A3 (PKCS#11): o modulo .so (ex.: libaetpkss.so) e o socket do
# pcscd do host precisam ser montados como volumes no deploy. Exemplo:
#   -v /usr/lib/libaetpkss.so:/usr/lib/libaetpkss.so:ro
#   -v /run/pcscd/pcscd.comm:/run/pcscd/pcscd.comm
# Detalhes de deploy ficam no Plano 2.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos "" --home /app app

COPY --from=builder /out/pjeheadless /app/pjeheadless

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 8800

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:${PJE_PJEOFFICE_PORT:-8800}/pjeOffice/ || exit 1

LABEL org.opencontainers.image.title="pjeoffice-headless" \
      org.opencontainers.image.description="Autenticador headless PJeOffice (CNJ) com assinatura dual A1/A3" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="2.0.0"

USER app
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
