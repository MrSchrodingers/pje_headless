#!/usr/bin/env bash
# proto/gen.sh — gera os stubs gRPC a partir de proto/signer.proto.
#
# Uso:
#   bash proto/gen.sh           (a partir da raiz do repositorio)
#
# Requisitos:
#   - protoc  (libprotoc >= 3.19)
#   - protoc-gen-go      (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)
#   - protoc-gen-go-grpc (go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest)
#
# SECURITY: plain TCP por padrao; mTLS e item de backlog.
# Nao expor a porta gRPC em redes nao-confiaveis sem TLS.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_DIR="${REPO_ROOT}/proto"
OUT_DIR="${REPO_ROOT}/internal/signerpb"

mkdir -p "${OUT_DIR}"

protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out="${OUT_DIR}" \
  --go_opt=paths=source_relative \
  --go-grpc_out="${OUT_DIR}" \
  --go-grpc_opt=paths=source_relative \
  "${PROTO_DIR}/signer.proto"

echo "stubs gerados em ${OUT_DIR}"
