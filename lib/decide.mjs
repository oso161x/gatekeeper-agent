// Pure decision logic for the Proof Gatekeeper event.
// No I/O, no secrets, no dependencies — unit-testable in isolation.
//
// Decision rules (from https://agentgames.zkverify.io/events/proof-gatekeeper):
//   APPROVE only when EVERY field check passes; otherwise REJECT with the
//   first matching trap reason code, in the documented order below.
//   Wrong APPROVE costs -6, wrong REJECT costs -3, so when in doubt REJECT.
//
// The circuit (circuits/gatekeeper.wasm) enforces exactly these checks:
//   decision=1 (APPROVE)  <=> all checks pass
//   decision=0 (REJECT)   <=> at least one check fails
// (verified empirically: witness generation fails on any mismatch — see
// circuits/CIRCUIT.md). PROOF_REUSED is the one trap the circuit cannot
// see (it needs a seen-set); the agent checks it in code and answers
// REJECT *without* a proof for reused references, per the event page
// ("PROOF_REUSED tasks have no proof to submit and are excluded").

// bn128 scalar field prime (used for all field-element encodings).
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Hex string ("0x..." or bare) -> field element (BigInt mod FIELD_PRIME). */
export function encodeHexToField(hex) {
  const s = String(hex).trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(s)) throw new Error(`not hex: ${hex}`);
  return BigInt('0x' + s) % FIELD_PRIME;
}

/**
 * Task id string -> field element.
 * ENCODING ASSUMPTION (see circuits/CIRCUIT.md): the UTF-8 bytes of the
 * task id, read as one big-endian integer, mod FIELD_PRIME.
 * The platform's exact conversion is not published; this is the standard
 * JS string->field conversion and the first thing to validate in practice
 * mode. It lives in exactly one place so it can be swapped.
 */
export function encodeTaskId(taskId) {
  const hex = Buffer.from(String(taskId), 'utf8').toString('hex');
  return BigInt('0x' + hex) % FIELD_PRIME;
}

/** Decimal string or number -> BigInt. */
export function encodeNumber(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error(`not an integer: ${v}`);
    return BigInt(v);
  }
  const s = String(v).trim();
  if (!/^-?\d+$/.test(s)) throw new Error(`not an integer: ${v}`);
  return BigInt(s);
}

function normHex(v) {
  return String(v).trim().toLowerCase();
}

/**
 * Decide a task.
 * @param {object} input  the task's `input` object (registered_vk, proof_vk,
 *   minimum, public_balance, expiry_block, current_block, recipient,
 *   condition_recipient, amount, max_transfer, proof_tx)
 * @param {(proofTx: string) => boolean} isSeen  reuse oracle for proof_tx
 * @returns {{decision: 'APPROVE'|'REJECT', reasonCode: string}}
 * @throws on missing/invalid fields (caller turns this into HTTP 400)
 */
export function decide(input, isSeen) {
  if (!input || typeof input !== 'object') throw new Error('missing input');
  const required = [
    'registered_vk', 'proof_vk', 'minimum', 'public_balance',
    'expiry_block', 'current_block', 'recipient', 'condition_recipient',
    'amount', 'max_transfer', 'proof_tx',
  ];
  for (const k of required) {
    if (input[k] === undefined || input[k] === null || input[k] === '') {
      throw new Error(`missing input field: ${k}`);
    }
  }

  // 1. VK_SUBSTITUTION — proof VK must match the registered condition VK.
  if (normHex(input.proof_vk) !== normHex(input.registered_vk)) {
    return { decision: 'REJECT', reasonCode: 'VK_SUBSTITUTION' };
  }
  // 2. THRESHOLD_MISMATCH — public balance must meet the minimum.
  if (encodeNumber(input.public_balance) < encodeNumber(input.minimum)) {
    return { decision: 'REJECT', reasonCode: 'THRESHOLD_MISMATCH' };
  }
  // 3. PROOF_REUSED — reference must not have been accepted before.
  if (isSeen(String(input.proof_tx))) {
    return { decision: 'REJECT', reasonCode: 'PROOF_REUSED' };
  }
  // 4. EXPIRED_CONDITION — current block must not pass the expiry block.
  if (encodeNumber(input.current_block) > encodeNumber(input.expiry_block)) {
    return { decision: 'REJECT', reasonCode: 'EXPIRED_CONDITION' };
  }
  // 5. RECIPIENT_MISMATCH — recipient must match the condition address.
  if (normHex(input.recipient) !== normHex(input.condition_recipient)) {
    return { decision: 'REJECT', reasonCode: 'RECIPIENT_MISMATCH' };
  }
  // 6. AMOUNT_OVERFLOW — amount must not exceed the single-transfer cap.
  if (encodeNumber(input.amount) > encodeNumber(input.max_transfer)) {
    return { decision: 'REJECT', reasonCode: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reasonCode: 'VALID_CONDITION' };
}

/**
 * Build the 13 circuit inputs for a decision.
 * All values are decimal strings (snarkjs accepts stringified BigInts).
 * Public-signal layout (verified, see circuits/CIRCUIT.md):
 *   [Poseidon([salt, taskId]), registeredVkHash, proofVkHash, minimum,
 *    publicBalance, expiryBlock, currentBlock, recipient,
 *    conditionRecipient, amount, maxTransfer, decision, taskId]
 * `salt` is the only private input.
 */
export function buildCircuitInput(taskId, input, decision, salt) {
  const dec = decision === 'APPROVE' ? 1n : 0n;
  return {
    taskId: encodeTaskId(taskId).toString(),
    registeredVkHash: encodeHexToField(input.registered_vk).toString(),
    proofVkHash: encodeHexToField(input.proof_vk).toString(),
    minimum: encodeNumber(input.minimum).toString(),
    publicBalance: encodeNumber(input.public_balance).toString(),
    expiryBlock: encodeNumber(input.expiry_block).toString(),
    currentBlock: encodeNumber(input.current_block).toString(),
    recipient: encodeHexToField(input.recipient).toString(),
    conditionRecipient: encodeHexToField(input.condition_recipient).toString(),
    amount: encodeNumber(input.amount).toString(),
    maxTransfer: encodeNumber(input.max_transfer).toString(),
    decision: dec.toString(),
    salt: (BigInt(salt) % FIELD_PRIME).toString(),
  };
}
