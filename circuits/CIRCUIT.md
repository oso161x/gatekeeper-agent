# Gatekeeper circuit — reverse-engineered spec

The platform publishes only the compiled artifacts (`gatekeeper.wasm`,
`gatekeeper_final.zkey`) and the vk hash — no circuit source, no input
schema. Everything below was recovered empirically from the artifacts
and is verified by the test suite (`npm test` generates real proofs and
verifies them locally against the exported `vk.json`).

## Sources

- Artifacts: https://agentgames.zkverify.io/circuits/gatekeeper.wasm
  (sha256 `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`),
  https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
  (sha256 `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`)
- vk hash (registered on zkVerify mainnet, `/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Protocol: Groth16 / BN128 (circom 2.x). 647 wires.

## How the inputs were found

`snarkjs zkey export verificationkey` gives `nPublic = 13`. Probing the
wasm with `circom_runtime`'s witness calculator (`getInputSignalSize`
returns the signal size, 0 for unknown names) yields exactly 13 input
signals, all scalars:

| signal | meaning |
|---|---|
| `taskId` | task id, as a field element (see Encoding) |
| `registeredVkHash` | registered condition VK, hex -> field |
| `proofVkHash` | proof VK, hex -> field |
| `minimum` | required minimum public balance |
| `publicBalance` | public balance disclosed in the proof |
| `expiryBlock` | condition expiry block height |
| `currentBlock` | current block height |
| `recipient` | payment recipient address, hex -> field |
| `conditionRecipient` | condition recipient address, hex -> field |
| `amount` | requested payment amount |
| `maxTransfer` | single-transfer cap |
| `decision` | 1 = APPROVE, 0 = REJECT |
| `salt` | private blinding input (only non-public input) |

## Public-signal layout (witness indices 1..13)

```
[ Poseidon([salt, taskId]),
  registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId ]
```

- `publicSignals[0]` is a commitment `Poseidon([salt, taskId])`
  (confirmed: `Poseidon([777, 1])` reproduces the witness value for
  `salt=777, taskId=1`). The salt is private, so the platform cannot
  recompute the commitment — it binds the proof to the task and makes
  each proof unique.
- `decision` is the only computed enforcement: the circuit template
  `GatekeeperEvaluation` asserts `decision == 1` iff every check passes
  and `decision == 0` iff at least one fails. Verified for all 6 trap
  types: a mismatched decision makes witness generation fail
  (assert, line 102), so **a decision cannot be faked** — a proof only
  exists for the circuit's own verdict.
- `reason_code` is NOT a circuit input. It is the agent's own
  classification (first matching trap, documented order) and is not
  proven by the circuit.
- `proof_tx` is NOT a circuit input either. Reuse is enforced by the
  agent's seen-set in code; PROOF_REUSED answers carry no proof at all
  (per the event page, those tasks "have no proof to submit").

## Value encodings (assumptions — validate in practice mode!)

| task field | circuit value |
|---|---|
| `task_id` (string, e.g. `"gk_24_9d1"`) | UTF-8 bytes as one big-endian integer, mod FIELD_PRIME |
| hex hashes/addresses (`0x...`) | `BigInt(hex) mod FIELD_PRIME` |
| decimal numbers/strings | `BigInt(value)` directly |
| `decision` | APPROVE = 1, REJECT = 0 |
| `salt` | fresh random 128-bit value per proof |

The platform's exact `task_id` conversion is **not published**. The
UTF-8-bytes conversion above is the standard JS string-to-field
conversion and is the default in `lib/decide.mjs:encodeTaskId()` — one
function, one place, easy to swap. The first practice task is the
moment of truth: if the platform rejects proofs, the encoding is the
first suspect (alternatives: keccak256 of the string mod p, or the
numeric suffix only). Everything else in the encoding table is forced
by the field arithmetic and needs no guessing.

## What the platform checks (inferred)

1. The Groth16 proof verifies against the platform's own registered VK.
2. `publicSignals[1..12]` match the task fields under the platform's
   encoding (this is where the `task_id` encoding matters).
3. The decision is correct — enforced by the circuit itself, not by
   re-running the checks.

## HMAC (assumption — confirmed at preflight)

`x-agent-games-signature` = HMAC-SHA256 (hex) over the raw request /
response body. Verification also accepts base64 and an optional
`sha256=` prefix. Preflight is the first live check of this format.
