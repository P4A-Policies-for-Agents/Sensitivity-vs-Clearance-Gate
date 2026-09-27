#!/usr/bin/env bash
# C1 Sensitivity vs Clearance Gate — run the before/after demo.
# Prereqs: the mocked "items" API is provisioned in A2D and fronted by a Flex
# Gateway route with this policy applied (see PROVISION.md), and env.local.sh sets
# C1_GW_URL. Usage:  source demo/env.local.sh && ./demo/demo.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${C1_GW_URL:-}" ]]; then
  echo "C1_GW_URL is not set. Copy env.local.sh.example to env.local.sh, edit it, then:" >&2
  echo "  source demo/env.local.sh && ./demo/demo.sh" >&2
  exit 1
fi

exec python3 "$here/driver.py"
