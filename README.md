# Sensitivity vs Clearance Gate — MuleSoft Omni/Flex Gateway Policy

A **response-leg (outbound)** gate for the MuleSoft Omni/Flex Gateway that decides,
per response, whether **what is about to be returned is too sensitive for who is
asking**. It classifies the response with a typed **"System 1" Jev judge** — a
probability distribution over sensitivity levels plus a personal-data probability,
never generated text — then compares that distribution to the **caller's clearance**
and blocks the response when it exceeds it. Applies to **REST**, **HTTP**, and **MCP**
(`assetTypes: rest,http,mcp`).

It is a member of the **TypeSafe-Jev** gateway policy family (sibling to S1, the MCP
Tool-Result Injection Screen): the judge returns *probabilities*, so **no model sits in
the data path** and nothing generated is ever inserted into the payload. All comparison
and mutation stays in Rust.

> **Deployment status:** the policy is **code-complete and unit-tested** (`cargo test`
> passing) and **published to Anypoint Exchange** (`sensitivity-clearance-gate` +
> `sensitivity-clearance-gate-flex`). Its A2D mock and Flex proxy route correctly. The
> live end-to-end demo on the shared `omni-gw-small` gateway is currently **blocked**: on
> this gateway build, applying the compiled policy to a running replica wedges the shared
> flex gateway at `STARTING` (a data-plane policy-load failure that does not reproduce in
> the local `wasm32-wasip1` build or unit tests, and could not be root-caused without
> data-plane logs). The policy is therefore shipped here as code-complete; the live demo
> is pending a gateway-side fix.

## The core idea — probability MASS above clearance, not a score

A "score" question ("rate the sensitivity 0–3") is only weakly calibrated *as a
number*. So the policy does **not** ask the judge for a number and compare it to the
clearance. Instead the judge returns a **distribution** over the configured levels
(e.g. `public / internal / confidential / restricted`), and the policy computes, in
Rust:

```
p_exceeds = Σ probabilities[level]   for every level strictly above the caller's clearance
```

— the probability the content is *more sensitive than the caller is cleared for*. That
mass is what the flag/block bands act on. The judge is never asked to compare a
sensitivity to a clearance.

## How it decides — resolve clearance → classify → compare → act

**Request leg** (no judge call): strip inbound `x-jev-*` headers, then resolve the
caller's clearance in order:
1. a **JWT claim** (`clearanceClaim`, default `data_clearance`) — decoded only when
   `trustUnverifiedClaims` is on (a JWT-validation policy should run first);
2. a **header** (`clearanceHeader`, default `x-data-clearance`);
3. `defaultClearance` (default `internal`).

Also resolves any per-route floor from `routeFloor`.

**Response leg**, for a 2xx response in scope:
1. **Extract** the classifiable text — MCP `tools/call` result text, an
   OpenAI-compatible LLM completion's assistant text, or the REST/HTTP body (optionally
   narrowed to `jsonPaths`).
2. **Classify** with the judge: a `score` question `sensitivity` (levels + descriptions
   from `levels` / `levelDescriptions`) and a `noul` question `has_personal_data`.
3. **Compare** — compute `p_exceeds` against the caller's clearance ordinal.
4. **Decide**, in priority order:
   - **`routeFloor`** — a route known to serve data at least this sensitive blocks a
     caller below the floor *without calling the judge*;
   - **`personalDataMinClearance`** — `has_personal_data ≥ 0.8` and a caller below this
     clearance is a block;
   - **bands** — block when `p_exceeds ≥ blockAt` (default 0.6), flag at `flagAt`
     (default 0.3).
5. **Act** per asset type:
   - **REST/HTTP** → replace the body with `{"error":"insufficient_clearance","policy":"sensitivity-clearance-gate","reason":…}`;
   - **LLM** → a **schema-preserving safe reply** (assistant content replaced with
     `safeReplyText`, everything else intact);
   - **MCP** → a valid JSON-RPC result with `isError:true` preserving the id.

`mode` is `enforce` / `shadow` (compute + log, never mutate — the safe first
deployment) / `off`. `failMode` is `open` (pass through on judge error/timeout) /
`closed` (block). The decision log records an FNV-1a fingerprint of the classified
text, not the text itself (unless `logStateSample`).

> **Response-leg status note:** a block replaces the response *body* and leaves the
> HTTP status unchanged. Emitting a true 403 (or an `x-jev-sensitivity` flag header)
> after reading the body needs the combined `into_headers_body_state()`, which can hang
> the response leg on Omni/Flex 1.12.1 — so the block is signalled in the body. See
> [`demo/WALKTHROUGH.md`](demo/WALKTHROUGH.md).

## Judge providers

Same contract as the rest of the family: `typesafe` (default, decisions API, model
`~typesafe/jev-latest`), any OpenAI-compatible chat endpoint (`openai` / `openrouter` /
`litellm` / `custom`) driven as a JSON classifier, `cloudflare`, and a deterministic
in-policy `mock` for tests and offline demos (`allowMock: true`). Full schema:
[`sensitivity-clearance-gate-definition/gcl.yaml`](sensitivity-clearance-gate-definition/gcl.yaml).

## Configuration (highlights)

| Property | Default | Purpose |
|---|---|---|
| `mode` | `shadow` | `enforce` / `shadow` / `off` |
| `failMode` | `open` | `open` / `closed` on judge error/timeout |
| `jevProvider` | `typesafe` | judge provider (`mock` for offline) |
| `jevService` | — (required) | judge base URL (`format: service`) |
| `levels` | `[public,internal,confidential,restricted]` | ordered sensitivity/clearance levels |
| `levelDescriptions` | (built-in) | descriptions aligned to `levels` the judge scores against |
| `clearanceClaim` / `clearanceHeader` / `defaultClearance` | `data_clearance` / `x-data-clearance` / `internal` | clearance resolution |
| `trustUnverifiedClaims` | `false` | decode the JWT claim without verifying (JWT policy first) |
| `routeFloor` | `[]` | `pathPrefix=level` floors enforced without the judge |
| `personalDataMinClearance` | `confidential` | min clearance to receive personal data |
| `flagAt` / `blockAt` | `0.3` / `0.6` | flag / block on mass above clearance (`blockAt ≥ flagAt`) |
| `safeReplyText` | `I can't share that information.` | LLM block replacement |
| `jsonPaths` | `[]` | classify only these JSON pointers of a REST body |
| `assetType` | `auto` | `rest` / `http` / `mcp` / `auto` |
| `maxBodyBytes` / `onOversize` | `1 MiB` / `skip` | oversize handling |
| `sampleRate` | `1.0` | fraction of eligible responses classified |

## Layout & build (split-model)

```
sensitivity-clearance-gate-definition/   # gcl.yaml + exchange.json — the applyable policy asset
sensitivity-clearance-gate-flex/          # Rust/wasm implementation
  src/ common.rs   # Mode/FailMode/Decision/Bands, glob, fnv1a  (shared spine)
      jev.rs       # Provider / JevSettings / evaluate + score/noul question layer + mock
      payloads.rs  # REST/jsonPaths + LLM safe-reply + MCP result + JWT claim decode
      screen.rs    # Signals + p_exceeds (mass above clearance) + decide (floor/PII/bands)
      lib.rs       # request-leg clearance resolution, response-leg classify/decide/act
demo/                                      # offline mock-judge demo + live-provisioning runbook
```

```bash
cargo build --target wasm32-wasip1 --release      # in sensitivity-clearance-gate-flex
cargo test  --lib                                  # 34 unit tests
```
Requires PDK 1.10 (feature `enable_stop_iteration`), cargo-anypoint, anypoint-cli-v4.
To publish + demo live, see [`demo/PROVISION.md`](demo/PROVISION.md) (publish DEFINITION
first, then the flex implementation).

## Demo

The same endpoint `GET /items/{id}` returns a **public product blurb** and a
**customer record with restricted personal data**. An `internal`-clearance caller gets
the blurb but is **blocked** on the record; a `restricted`-clearance caller gets the
record. Deterministic mock judge — no credentials:

```bash
cp demo/config.json.example demo/config.json      # mock judge — no creds
cp demo/env.local.sh.example demo/env.local.sh     # set C1_GW_URL
source demo/env.local.sh && ./demo/demo.sh
```
See [`demo/WALKTHROUGH.md`](demo/WALKTHROUGH.md) for the full story.
