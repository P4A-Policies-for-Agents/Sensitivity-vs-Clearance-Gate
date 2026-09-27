# C1 Sensitivity vs Clearance Gate — walkthrough

## The story

An internal "items" API serves everything from public marketing blurbs to customer
records holding restricted personal data (name + email + date of birth + SSN + a
medical note). Different callers hold different **data clearances**. Nothing on the
response path today checks whether *what is about to be returned* is too sensitive for
*who is asking* — so a customer record can flow to a caller who should only ever see
public and internal data.

The **Sensitivity vs Clearance Gate** sits on the response leg. For each response it
asks a typed **Jev** judge two questions — *how sensitive is this content?* (a
probability distribution over `public / internal / confidential / restricted`) and
*does it contain personal data?* — then, entirely in Rust, computes the probability
**mass above the caller's clearance** and blocks when that mass crosses a threshold.
The judge never sees the clearance and is never asked to compare anything; it only
classifies. All mutation stays in the policy.

## The exact demo scenario

The **same endpoint** `GET /items/{id}` returns content of very different sensitivity:

| # | Caller clearance | Request | Content | Outcome |
|---|---|---|---|---|
| 1 | `internal` | `GET /items/blurb` | public product blurb | **allowed** — mass above `internal` is ~0.07 (< flagAt 0.3) |
| 2 | `internal` | `GET /items/record` | restricted customer record | **blocked** — mass above `internal` (confidential+restricted) ≈ 0.9 (≥ blockAt 0.6), and the personal-data rule also fires (`has_personal_data` ≥ 0.8, caller below `confidential`) |
| 3 | `restricted` | `GET /items/record` | the *same* record | **allowed** — nothing is above a `restricted` caller, so mass above clearance is 0 |

The caller's clearance rides in the `x-data-clearance` header (the policy's
`clearanceHeader`). A JWT `data_clearance` claim does the same when
`trustUnverifiedClaims` is enabled (a JWT-validation policy should run first).

A blocked response body is:
```json
{ "error": "insufficient_clearance", "policy": "sensitivity-clearance-gate", "reason": "personal_data_above_clearance" }
```
(`reason` is one of `route_floor`, `personal_data_above_clearance`,
`sensitivity_exceeds_clearance`.)

## Why the same record is allowed to one caller and blocked for another

The judge classifies the **content** once; the *decision* is per-caller because
`p_exceeds` is measured against each caller's clearance ordinal. The record classifies
as mostly `restricted`. For an `internal` caller almost all of that mass sits above
their clearance → block. For a `restricted` caller none of it does → allow. Same bytes,
different caller, different outcome — with no model in the data path.

## Actions per asset type

- **REST/HTTP** (this demo): a block replaces the body with the
  `insufficient_clearance` error object above.
- **LLM chat** (OpenAI-compatible completion): a block becomes a *schema-preserving
  safe reply* — every `choices[].message.content` is replaced with `safeReplyText`
  ("I can't share that information.") while ids, model, role, finish_reason and usage
  are preserved, so the client still gets a valid completion.
- **MCP** (`tools/call` result): a block becomes a valid JSON-RPC result with
  `isError: true` preserving the request id.

## ⚠️ Response-leg HTTP status / flag-header limitation (VERIFY)

This policy blocks by **replacing the response body**, and leaves the HTTP status as
returned by the upstream (typically `200`). That is deliberate and runtime-safe:

- Emitting a real **HTTP 403** on the response leg, or adding an `x-jev-sensitivity`
  flag header *after* reading the body, requires the combined
  `into_headers_body_state()` state (`handler.set_header(":status", "403")`), because
  the split event-flow path freezes headers before the body is read.
- The combined state is subject to a **response-leg hang on Omni/Flex 1.12.1** (returns
  Envoy 504 instead of the transformed response), observed across multiple
  response-shaping policies. So this policy uses the split flow by default and signals
  the block in the **body** (machine-readable `error: insufficient_clearance`), which
  every client can act on regardless of status.
- To opt into a true 403 + flag header, switch `response_filter` to
  `into_headers_body_state()` and set `:status` / `x-jev-sensitivity` there — **only
  after verifying the combined state does not hang on your target runtime.** A `flag`
  decision is currently recorded in the policy decision log (argmax level) rather than
  as a header, for the same reason.

## Offline / no-gateway sanity check

You don't need the gateway to see the decision logic: the deterministic mock judge and
the full decision path are unit-tested. Run `cargo test --lib` in
`sensitivity-clearance-gate-flex` — see
`restricted_pii_blocks_internal_caller_allows_restricted_caller`,
`public_blurb_allows_internal_caller`, and `clearance_resolution_order_*`.
