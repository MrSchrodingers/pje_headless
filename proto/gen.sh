#!/usr/bin/env bash
# proto/gen.sh — generates gRPC stubs from proto/signer.proto and proto/login.proto.
#
# Usage:
#   bash proto/gen.sh           (from the repository root)
#
# Requirements:
#   - protoc  (libprotoc >= 3.19)
#   - protoc-gen-go      (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)
#   - protoc-gen-go-grpc (go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest)
#
# SECURITY: plain TCP by default; mTLS is a backlog item.
# Do NOT expose the gRPC ports on untrusted networks without TLS.
# The bearer token returned by LoginService is a credential; treat accordingly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_DIR="${REPO_ROOT}/proto"

# --- SignerService ---
SIGNER_OUT="${REPO_ROOT}/internal/signerpb"
mkdir -p "${SIGNER_OUT}"

protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out="${SIGNER_OUT}" \
  --go_opt=paths=source_relative \
  --go-grpc_out="${SIGNER_OUT}" \
  --go-grpc_opt=paths=source_relative \
  "${PROTO_DIR}/signer.proto"

echo "signer stubs generated in ${SIGNER_OUT}"

# --- LoginService ---
LOGIN_OUT="${REPO_ROOT}/internal/loginpb"
mkdir -p "${LOGIN_OUT}"

protoc \
  --proto_path="${PROTO_DIR}" \
  --go_out="${LOGIN_OUT}" \
  --go_opt=paths=source_relative \
  --go-grpc_out="${LOGIN_OUT}" \
  --go-grpc_opt=paths=source_relative \
  "${PROTO_DIR}/login.proto"

echo "login stubs generated in ${LOGIN_OUT}"
