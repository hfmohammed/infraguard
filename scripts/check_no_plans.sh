#!/usr/bin/env bash
set -euo pipefail

bad="$(git ls-files | grep -E '(^|/)(tfplan([^/]*|$)|plan\.json)$|\.tfplan$|\.tfstate($|\.)|(^|/)\.terraform/' || true)"
allowed="$(printf '%s\n' "$bad" | grep -E '^samples/terraform/plan-fixtures/.*\.plan\.fixture\.json$' || true)"
if [[ -n "$allowed" ]]; then
  bad="$(comm -23 <(printf '%s\n' "$bad" | sort) <(printf '%s\n' "$allowed" | sort))"
fi
if [[ -n "$bad" ]]; then
  echo "Refusing tracked Terraform plan/state artifacts:" >&2
  echo "$bad" >&2
  exit 1
fi

