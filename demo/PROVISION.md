# C1 Sensitivity vs Clearance Gate — live demo runbook

Stand up a mocked REST API in **A2D**, front it with a **Flex Gateway** route on
**omni-gw-small**, apply the **Sensitivity vs Clearance Gate** policy in `enforce` with
the deterministic **mock** judge, and run the before/after driver.

> All tenant ids, hostnames, and org ids below are **placeholders** — replace with
> your own. Never commit real ids or keys. This runbook is the Phase-B (outward)
> procedure; the policy itself is built and unit-tested in Phase A.

## 0. Prerequisites
- Exchange group id: `030e0aac-30d9-460f-9234-428c16a123c4`
- `anypoint-cli-v4` logged in to your org/environment
- PDK 1.10 toolchain (cargo-anypoint, `wasm32-wasip1`)
- A running Flex Gateway instance registered to your org (use **omni-gw-small** — it
  has a public URL; omni-gw-ps-large is internal-only and 404s externally)

## 1. Publish the policy (definition first, then implementation)
```bash
# DEFINITION first — the flex impl's config-gen runs against the published definition.
make -C sensitivity-clearance-gate-definition release   # pdk policy-definition publish
make -C sensitivity-clearance-gate-flex       release   # build-asset-files + build + policy-wasm publish
```
`make -C …-flex release` regenerates `src/generated/config.rs` from the published
definition (overwriting the hand-written Phase-A copy) before building.

## 2. Create the mocked "items" API in A2D
Use the A2D MCP tools (or the UI) to create a REST API from `demo/api-spec.yaml`:
- One resource `GET /items/{id}` with two mock scenarios keyed by `id`:
  - `blurb`  → the **public product blurb** example body
  - `record` → the **customer record with restricted personal data** example body
- Publish the mock and note its base URL → this is `C1_RAW_URL`.

## 3. Front it with a Flex Gateway route + apply the policy
1. Create an API instance in API Manager for the mocked upstream on **omni-gw-small**,
   note the **API instance id** and the route base URL → this is `C1_GW_URL` (…/items).
2. Apply the policy to that instance (outbound/response-leg policy):
   ```bash
   anypoint-cli-v4 api-mgr policy apply <API_INSTANCE_ID> \
     030e0aac-30d9-460f-9234-428c16a123c4 sensitivity-clearance-gate 1.0.0 \
     --config "$(cat demo/config.json)"
   ```
   (Copy `demo/config.json.example` → `demo/config.json` first; it uses the mock judge,
   `mode: enforce`, `clearanceHeader: x-data-clearance`, `defaultClearance: internal`.)
   > Upgrading later: `policy remove` the old policy id, then `policy apply` the new
   > version — never delete+recreate the same Exchange version (schema-not-found).

## 4. Run the demo
```bash
cp demo/config.json.example demo/config.json      # mock judge — no creds
cp demo/env.local.sh.example demo/env.local.sh    # set C1_GW_URL (+ optional C1_RAW_URL)
source demo/env.local.sh && ./demo/demo.sh
```
Expected: caller `internal` gets the blurb but is **blocked** on the record
(`insufficient_clearance`); caller `restricted` gets the record. See `WALKTHROUGH.md`.

## 5. Teardown
```bash
anypoint-cli-v4 api-mgr policy remove <API_INSTANCE_ID> <POLICY_ID>
# optionally delete the API instance and the A2D mock.
```
