#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

IDS_AUTH_DISABLED=1 python3 -m unittest discover -s tests -p "test_*.py"
