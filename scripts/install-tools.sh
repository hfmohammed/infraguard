#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin
echo "External tools are installed on demand. See tools.env for pinned versions."
for tool in kind kubectl helm conftest opa kubeconform terraform; do
  if command -v "$tool" >/dev/null; then
    "$tool" version >/dev/null 2>&1 || "$tool" --version >/dev/null 2>&1 || true
    echo "found $tool"
  else
    echo "missing $tool (install the version pinned in tools.env for integration work)"
  fi
done

