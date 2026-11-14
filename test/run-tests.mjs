// Tests for gatekeeper-agent. Run: npm test
// Covers: decision logic (all 7 cases), encodings, HMAC, real Groth16
// proof generation + local verification, and the live HTTP server
// (health, preflight, 7 signed task POSTs, idempotency, PROOF_REUSED).

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  decide, buildCircuitInput, encodeTaskId, encodeHexToField, FIELD_PRIME,
} from '../lib/decide.mjs';
import { signHmac, verifyHmac, SIGNATURE_HEADER } from '../lib/hmac.mjs';
import { generateProof, verifyProofLocally, randomSalt } from '../lib/prove.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

let passed = 0;
function check(name, fn) {
  fn();
  passed += 1;
  console.log(`ok - ${name}`);
}

// ---------- fixtures: the event page's sample payload, full-length hex ----------
const VK_A = '0x7d3a00000000000000000000000000000000000000000000000000000000f291';
const VK_B = '0x13c10000000000000000000000000000000000000000000000000000000000aa';
const ADDR = '0xde4200000000000000000000000000000000009f01';
const TX = '0xa8c100000000000000000000000000000000000000000000000000000000002c';

function baseInput(over = {}) {
  return {
    registered_vk: VK_A,
    proof_vk: VK_A,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: '500',
    max_transfer: '1000',
    proof_tx: TX,
    ...over,
  };
}

// ---------- 1. decision logic: all 7 cases ----------
check('decide: valid -> APPROVE/VALID_CONDITION', () => {
  assert.deepEqual(decide(baseInput(), () => false), { decision: 'APPROVE', reasonCode: 'VALID_CONDITION' });
});
check('decide: VK_SUBSTITUTION', () => {
  assert.deepEqual(decide(baseInput({ proof_vk: VK_B }), () => false).reasonCode, 'VK_SUBSTITUTION');
});
check('decide: THRESHOLD_MISMATCH', () => {
  assert.deepEqual(decide(baseInput({ public_balance: '999' }), () => false).reasonCode, 'THRESHOLD_MISMATCH');
});
check('decide: PROOF_REUSED', () => {
  assert.deepEqual(decide(baseInput(), () => true).reasonCode, 'PROOF_REUSED');
});
check('decide: EXPIRED_CONDITION', () => {
  assert.deepEqual(decide(baseInput({ current_block: 8430001 }), () => false).reasonCode, 'EXPIRED_CONDITION');
});
check('decide: RECIPIENT_MISMATCH', () => {
  assert.deepEqual(
    decide(baseInput({ condition_recipient: '0x1111000000000000000000000000000000000001' }), () => false).reasonCode,
    'RECIPIENT_MISMATCH',
  );
});
check('decide: AMOUNT_OVERFLOW', () => {
  assert.deepEqual(decide(baseInput({ amount: '1001' }), () => false).reasonCode, 'AMOUNT_OVERFLOW');
});
check('decide: first trap wins (VK beats threshold)', () => {
  assert.deepEqual(
    decide(baseInput({ proof_vk: VK_B, public_balance: '1' }), () => false).reasonCode,
    'VK_SUBSTITUTION',
  );
});
check('decide: boundary values pass (balance==min, amount==cap, block==expiry)', () => {
  assert.deepEqual(
    decide(baseInput({ public_balance: '1000', amount: '1000', current_block: 8430000 }), () => false).decision,
    'APPROVE',
  );
});
check('decide: missing field throws', () => {
  assert.throws(() => decide({ registered_vk: VK_A }, () => false), /missing input field/);
});

// ---------- 2. encodings ----------
check('encodeTaskId: utf8 bytes as bigint', () => {
  assert.equal(encodeTaskId('gk_24_9d1'), BigInt('0x' + Buffer.from('gk_24_9d1').toString('hex')) % FIELD_PRIME);
});
check('encodeHexToField: address fits, hash reduced mod p', () => {
  assert.equal(encodeHexToField(ADDR), BigInt(ADDR) % FIELD_PRIME);
  assert.equal(encodeHexToField(VK_A), BigInt(VK_A) % FIELD_PRIME);
});

// ---------- 3. HMAC ----------
check('hmac: sign/verify round-trip, tamper fails', () => {
  const body = Buffer.from('{"a":1}');
  const sig = signHmac('s3cret', body);
  assert.equal(verifyHmac('s3cret', body, sig), true);
  assert.equal(verifyHmac('s3cret', Buffer.from('{"a":2}'), sig), false);
  assert.equal(verifyHmac('wrong', body, sig), false);
  assert.equal(verifyHmac('s3cret', body, ''), false);
  assert.equal(verifyHmac('s3cret', body, 'sha256=' + sig), true);
});

// ---------- 4. real proofs (Groth16, platform circuit) ----------
async function proofCase(name, taskId, input, decision) {
  const circuitInput = buildCircuitInput(taskId, input, decision, randomSalt());
  const { proof, publicSignals } = await generateProof(circuitInput);
  assert.equal(publicSignals.length, 13);
  assert.equal(await verifyProofLocally(proof, publicSignals), true);
  assert.equal(publicSignals[11], decision === 'APPROVE' ? '1' : '0');
  assert.equal(publicSignals[12], encodeTaskId(taskId).toString());
  passed += 1;
  console.log(`ok - proof: ${name} (local verify true)`);
}

await proofCase('valid APPROVE', 'gk_test_1', baseInput({ proof_tx: TX + '01' }), 'APPROVE');
await proofCase('VK mismatch REJECT', 'gk_test_2', baseInput({ proof_vk: VK_B, proof_tx: TX + '02' }), 'REJECT');

// ---------- 5. live HTTP server ----------
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-test-'));
const statePath = path.join(tmpDir, 'state.json');
const TEST_SECRET = 'test-hmac-secret-' + Date.now();
const PORT = 18711;
const serverProc = spawn(process.execPath, ['server.mjs'], {
  cwd: ROOT,
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: TEST_SECRET, GATEKEEPER_STATE_PATH: statePath },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverOut = '';
serverProc.stdout.on('data', (d) => { serverOut += d; });
serverProc.stderr.on('data', (d) => { serverOut += d; });

async function waitForHealth() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('server did not come up:\n' + serverOut);
}

function signedPost(pathname, bodyObj) {
  const body = JSON.stringify(bodyObj);
  return fetch(`http://127.0.0.1:${PORT}${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', [SIGNATURE_HEADER]: signHmac(TEST_SECRET, body) },
    body,
  });
}

try {
  await waitForHealth();

  const health = await (await fetch(`http://127.0.0.1:${PORT}/health`)).json();
  assert.equal(health.status, 'ok');
  assert.equal(health.proof.vkHash, '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0');
  passed += 1;
  console.log('ok - http: GET /health 200 + vkHash');

  // preflight
  const pre = await signedPost('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  assert.equal(pre.status, 200);
  const preRaw = await pre.text();
  assert.deepEqual(JSON.parse(preRaw), { ok: true, protocolVersion: 'v1' });
  assert.equal(verifyHmac(TEST_SECRET, preRaw, pre.headers.get(SIGNATURE_HEADER)), true);
  passed += 1;
  console.log('ok - http: preflight 200 + signed response');

  // unsigned task -> 401
  const unsigned = await fetch(`http://127.0.0.1:${PORT}/agent`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'x', input: baseInput() }),
  });
  assert.equal(unsigned.status, 401);
  passed += 1;
  console.log('ok - http: unsigned task -> 401');

  // 7 task cases, each with its own proof_tx
  const cases = [
    ['valid APPROVE', 'gk_live_1', baseInput({ proof_tx: TX + '11' }), 'APPROVE', 'VALID_CONDITION', true],
    ['VK_SUBSTITUTION', 'gk_live_2', baseInput({ proof_vk: VK_B, proof_tx: TX + '12' }), 'REJECT', 'VK_SUBSTITUTION', true],
    ['THRESHOLD_MISMATCH', 'gk_live_3', baseInput({ public_balance: '10', proof_tx: TX + '13' }), 'REJECT', 'THRESHOLD_MISMATCH', true],
    ['EXPIRED_CONDITION', 'gk_live_4', baseInput({ current_block: 9999999, proof_tx: TX + '14' }), 'REJECT', 'EXPIRED_CONDITION', true],
    ['RECIPIENT_MISMATCH', 'gk_live_5', baseInput({ condition_recipient: '0x2222000000000000000000000000000000000002', proof_tx: TX + '15' }), 'REJECT', 'RECIPIENT_MISMATCH', true],
    ['AMOUNT_OVERFLOW', 'gk_live_6', baseInput({ amount: '99999', proof_tx: TX + '16' }), 'REJECT', 'AMOUNT_OVERFLOW', true],
  ];
  for (const [name, taskId, input, wantDecision, wantCode, wantProof] of cases) {
    const bodyObj = { type: 'agent-games.proof-gatekeeper.v1', task_id: taskId, mode: 'competition', issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(), input };
    const r = await signedPost('/agent', bodyObj);
    assert.equal(r.status, 200, `${name}: http ${r.status}`);
    const raw = await r.text();
    assert.equal(verifyHmac(TEST_SECRET, raw, r.headers.get(SIGNATURE_HEADER)), true, `${name}: response signature`);
    const j = JSON.parse(raw);
    assert.equal(j.decision, wantDecision, `${name}: decision`);
    assert.equal(j.reason_code, wantCode, `${name}: reason_code`);
    assert.equal(j.proof_tx, input.proof_tx, `${name}: proof_tx echo`);
    assert.equal(Boolean(j.proof && j.public_signals), wantProof, `${name}: proof present`);
    if (j.proof) assert.equal(await verifyProofLocally(j.proof, j.public_signals), true, `${name}: proof verifies locally`);
    passed += 1;
    console.log(`ok - http: task ${name} -> ${wantDecision}/${wantCode} + proof verifies`);
  }

  // PROOF_REUSED: same proof_tx as case 1, new task_id -> REJECT, no proof
  const reuseBody = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_live_7', input: baseInput({ proof_tx: TX + '11' }) };
  const reuse = await signedPost('/agent', reuseBody);
  const reuseJson = await reuse.json();
  assert.equal(reuseJson.decision, 'REJECT');
  assert.equal(reuseJson.reason_code, 'PROOF_REUSED');
  assert.equal(reuseJson.proof, undefined);
  passed += 1;
  console.log('ok - http: PROOF_REUSED -> REJECT, no proof');

  // idempotency: replay case 1 verbatim -> identical response, still APPROVE
  const replayBody = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_live_1', mode: 'competition', issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(), input: baseInput({ proof_tx: TX + '11' }) };
  const replay = await signedPost('/agent', replayBody);
  const replayJson = await replay.json();
  assert.equal(replayJson.decision, 'APPROVE');
  assert.equal(replayJson.reason_code, 'VALID_CONDITION');
  assert.ok(replayJson.proof);
  passed += 1;
  console.log('ok - http: idempotent replay returns cached APPROVE');
} finally {
  serverProc.kill('SIGTERM');
}

console.log(`\n${passed} checks passed`);
// snarkjs keeps worker handles open after require(); exit explicitly.
process.exit(0);
