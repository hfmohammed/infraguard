#!/usr/bin/env bash
set -euo pipefail

echo "Fixtures are sanitized, reviewable JSON under samples/terraform/plan-fixtures/."
echo "Generation intentionally requires an explicit module argument and never applies."
if [[ $# -ne 1 ]]; then
  echo "usage: $0 <terraform-module-directory>" >&2
  exit 2
fi
echo "Use: terraform -chdir=$1 plan -refresh=false -out=<temporary path>; terraform show -json"

