#!/usr/bin/env bash
set -euo pipefail

# Configuracao via variaveis de ambiente.
# Consulte o README para a lista completa de variaveis suportadas.
# Segredos (PJE_PFX_PASS, PJE_PKCS11_PIN) devem ser injetados pelo orquestrador
# de containers (Docker secret, env file fora do repositorio) — nunca hardcoded.

exec /app/pjeheadless
