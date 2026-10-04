#!/usr/bin/env bash
# Run the API locally. Set EMLARCH_DATABASE_DSN to use PostgreSQL; without it
# an ephemeral in-memory store is used.
set -euo pipefail
cd "$(dirname "$0")"
export EMLARCH_ATTACHMENT_DIR="${EMLARCH_ATTACHMENT_DIR:-./data/attachments}"
export EMLARCH_RAW_DIR="${EMLARCH_RAW_DIR:-./data/raw}"
exec .venv/bin/uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8080}" "$@"
