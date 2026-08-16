#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="${1:-HEAD}"
timezone="${CPA_VERSION_TIMEZONE:-Asia/Shanghai}"

TZ="$timezone" git -C "$repo_dir" show -s \
  --date=format-local:%Y%m%d-%H%M%S \
  --format=%cd \
  "$ref"
