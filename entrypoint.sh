#!/usr/bin/env bash
set -euo pipefail

: "${PJE_CERT_PATH:?Set PJE_CERT_PATH to your mounted .pfx/.p12 file}"
: "${PJE_CERT_PASS:?Set PJE_CERT_PASS to your certificate password}"
PJE_PORT="${PJE_PORT:-8800}"

echo "➡️  Starting pjeoffice-headless on port ${PJE_PORT} with cert ${PJE_CERT_PATH}"
exec python -m pjeoffice_headless \
  --certificate "${PJE_CERT_PATH}" \
  --password "${PJE_CERT_PASS}" \
  --port "${PJE_PORT}"
