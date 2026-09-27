#!/usr/bin/env python3
"""C1 Sensitivity vs Clearance Gate — before/after demo driver.

Hits the SAME endpoint twice with different content and different caller clearances,
through the Flex Gateway route that has the policy applied, and prints what each
caller receives:

  1. internal caller  → GET /items/blurb   (a public product blurb)      → ALLOWED
  2. internal caller  → GET /items/record  (a record with restricted PII) → BLOCKED (insufficient_clearance)
  3. restricted caller→ GET /items/record  (the same record)             → ALLOWED

The caller's clearance is carried in the `x-data-clearance` header (the policy's
`clearanceHeader`); a JWT `data_clearance` claim works the same way when
`trustUnverifiedClaims` is on. No third-party packages — stdlib only.
"""
import json
import os
import sys
import urllib.request
import urllib.error

GW = os.environ.get("C1_GW_URL", "http://localhost:8081/items").rstrip("/")


def call(item: str, clearance: str):
    url = f"{GW}/{item}"
    req = urllib.request.Request(url, headers={"x-data-clearance": clearance, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, f"<request failed: {e}>"


def show(title: str, item: str, clearance: str):
    status, body = call(item, clearance)
    blocked = '"insufficient_clearance"' in body
    verdict = "BLOCKED" if blocked else "allowed"
    print(f"\n=== {title} ===")
    print(f"    GET /items/{item}   x-data-clearance: {clearance}")
    print(f"    HTTP {status}  → {verdict}")
    try:
        print("    " + json.dumps(json.loads(body), indent=2).replace("\n", "\n    "))
    except Exception:  # noqa: BLE001
        print("    " + body[:400])


def main():
    print(f"C1 demo → gateway route: {GW}")
    show("1. public blurb, internal caller (expect allowed)", "blurb", "internal")
    show("2. restricted PII record, internal caller (expect BLOCKED)", "record", "internal")
    show("3. same restricted PII record, restricted caller (expect allowed)", "record", "restricted")
    print("\nDone. Blocked responses carry {\"error\":\"insufficient_clearance\",\"policy\":\"sensitivity-clearance-gate\"}.")
    print("(See WALKTHROUGH.md on why the HTTP status stays 200 on the response leg.)")


if __name__ == "__main__":
    sys.exit(main())
