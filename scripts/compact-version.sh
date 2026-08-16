#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="${1:-HEAD}"
commit_date="$(git -C "$repo_dir" show -s --format=%cs "$ref")"
short_code="$(git -C "$repo_dir" rev-parse "$ref" | cut -c1-4)"

printf '%s%s-%s\n' "${commit_date:5:2}" "${commit_date:8:2}" "$short_code"
