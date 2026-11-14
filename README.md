# Gatekeeper Agent — Proof Gatekeeper, zkVerify Agent Games

A public HTTPS endpoint that judges proof-backed payment tasks and
attests every decision with a local Groth16 proof. Built for the
[Proof Gatekeeper](https://agentgames.zkverify.io/events/proof-gatekeeper)
track (100,000 VFY/track; 8 daily rounds 13–21 Nov 2026, 17:30–03:30 WIB).

## What it does

For each signed task (`agent-games.proof-gatekeeper.v1`) it:

1. Verifies the HMAC signature over the raw body **before** parsing.
2. Returns a cached response if `task_id` was already answered
   (idempotency — the platform may retry after a network failure).
3. Decides deterministically from the task fields (no AI, no guessing):
   APPROVE only if every check passes, else REJECT with the first
   matching trap code, in order: `VK_SUBSTITUTION`,
   `THRESHOLD_MISMATCH`, `PROOF_REUSED`, `EXPIRED_CONDITION`,
   `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`.
4. Generates a Groth16 proof of the decision with the platform's own
   circuit artifacts (snarkjs, ~1s) and returns
   `{decision, reason_code, proof, public_signals, proof_tx}`, signed
   with `x-agent-games-signature` over the raw response body.
5. Records `proof_tx` in the seen-set; `PROOF_REUSED` answers carry no
   proof (per the event rules) and a repeated `proof_tx` is rejected.

Preflight (`agent-games.preflight.v1`) answers
`{ok: true, protocolVersion: "v1"}`, signed. `GET /health` is public.

Scoring note: a correct decision without a proof is still +10 (+12 −2),
so if proof generation ever fails the agent answers the decision bare
rather than timing out (−2).

## Layout

```
server.mjs            HTTP server, HMAC gate, preflight, task handler
lib/decide.mjs        pure decision logic + field encodings (no I/O)
lib/hmac.mjs          HMAC-SHA256 sign/verify (stdlib crypto)
lib/prove.mjs         snarkjs Groth16 proving (lazy createRequire)
lib/store.mjs         seen-set + idempotency cache (data/state.json)
lib/kurier.mjs        optional async Kurier audit (never blocks a response)
circuits/             platform artifacts + CIRCUIT.md (reverse-eng. spec)
test/run-tests.mjs    decision/encoding/HMAC/proof/HTTP test suite
```

## Run locally

```bash
npm install
npm test            # decision logic, encodings, HMAC, real proofs, HTTP server
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET (test value for local runs)
npm start           # listens on $PORT (default 3000)
```

## Deploy (Railway)

```bash
railway link            # or `railway init` for a new project
railway up -y -d
railway variables set AGENT_GAMES_HMAC_SECRET=<secret from Rotate Secret>
```

`GET /health` must return 200. The registered endpoint URL is
`https://<railway-domain>/agent`.

## Registration checklist (owner, from the dashboard)

1. Register the agent with the public endpoint URL (`.../agent`).
2. **Rotate Secret** on the dashboard, copy the one-time plaintext,
   set it as `AGENT_GAMES_HMAC_SECRET` in Railway, restart the service.
   (Until then the agent answers 503 on tasks — fail closed.)
3. Run **preflight** from the dashboard — must pass before the agent is
   marked active. If it fails with a signature error, the secret in
   Railway does not match the platform's current secret.
4. Do at least one **practice task** and check the dashboard verdict:
   - If proofs are rejected, the first suspect is the `task_id`
     encoding — see `circuits/CIRCUIT.md` ("Value encodings").
   - If preflight fails, the suspect is the HMAC format (hex assumed).
5. Enter the Proof Gatekeeper event. Rounds run 17:30–03:30 WIB;
   round 3 opens 15 Nov 17:30 WIB. Scores are cumulative; rounds 1–2
   are already missed.

## Known limitations (honest)

- **Proof encodings are partly assumed.** The circuit inputs, public
  layout, decision encoding (1/0) and the Poseidon commitment were all
  verified empirically against the published artifacts — but the
  platform's exact `task_id` string-to-field conversion is unpublished
  and can only be confirmed by the first practice task. It is isolated
  in `encodeTaskId()` for a one-line fix.
- **On-chain proof check is not done.** The task payload carries only
  `proof_tx` (a reference), not the proof itself, so the agent cannot
  independently confirm the external proof is on-chain; it trusts the
  platform's own reference and checks the fields — which is exactly
  what the 7 documented traps test.
- **Seen-set is a local file.** Railway's filesystem is ephemeral: a
  restart loses the seen-set (a repeated `proof_tx` straddling a
  restart could be misjudged) and the idempotency cache (a retry is
  re-decided from fields — harmless). See `lib/store.mjs` for the
  trade-off and mitigations.
- **Dependencies.** The HTTP/HMAC/decision core is Node stdlib-only;
  local proving needs `snarkjs` (the platform's documented tool) as
  the single declared dependency. The ESM `import * as snarkjs` path
  hangs on this Node version — it is loaded via `createRequire`
  (verified: fullProve ~1s in-process).
- **Kurier audit is optional and async.** The 60s task deadline cannot
  fit a Kurier round-trip (~2–6 min to Finalized), so submission runs
  in the background after responding, only when `KURIER_API_KEY`
  (mainnet) is set. The platform re-verifies proofs itself; Kurier is
  an independent audit trail, not a scoring input.
