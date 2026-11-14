// Proof Gatekeeper agent — public HTTPS endpoint for zkVerify Agent Games.
// Node stdlib only for the HTTP/HMAC/decision layer; proof generation uses
// snarkjs (see lib/prove.mjs for why).
//
// Routes:
//   GET  /health          -> {status, service, version, proof:{configured, vkHash}}
//   POST /agent           -> task + preflight endpoint (the registered URL)
//   POST /                -> alias of /agent (defensive: the platform posts
//                            to the URL exactly as registered)
//
// Protocol (https://agentgames.zkverify.io/build):
//   - Every inbound request is HMAC-signed (x-agent-games-signature over
//     the RAW body). Verify BEFORE parsing. No secret configured -> 503
//     (fail closed; the secret comes from Rotate Secret on the dashboard).
//   - Preflight {type:"agent-games.preflight.v1"} -> {ok:true,
//     protocolVersion:"v1"}, signed.
//   - Task {type:"agent-games.proof-gatekeeper.v1", task_id, input:{...}}
//     -> {decision, reason_code, proof, public_signals, proof_tx}, signed.
//     PROOF_REUSED answers carry no proof (excluded by the event rules).
//   - task_id is the idempotency key: a retry returns the cached response
//     verbatim (checked BEFORE the seen-set, so a retry is never
//     misread as a reuse).
//   - If proof generation fails, the decision is still answered without a
//     proof (correct decision +12, missing proof -2 = +10 beats a -2
//     timeout). The failure is logged for investigation.
//   - Never log the HMAC secret. Never approve by default.

import http from 'node:http';
import { randomUUID } from 'node:crypto';

import { decide, buildCircuitInput } from './lib/decide.mjs';
import { signHmac, verifyHmac, SIGNATURE_HEADER } from './lib/hmac.mjs';
import { generateProof, randomSalt, GATEKEEPER_VK_HASH } from './lib/prove.mjs';
import { createStore } from './lib/store.mjs';
import { submitProofAudit } from './lib/kurier.mjs';

const VERSION = '0.1.0';
const PORT = Number(process.env.PORT || 3000);
const MAX_BODY_BYTES = 1_000_000;

const store = createStore();
const { seenCount, cachedCount, loaded } = store.load();

function log(obj) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

log({ level: 'info', msg: 'gatekeeper-agent boot', version: VERSION, stateLoaded: loaded, seenCount, cachedCount });

function sendJson(res, status, obj, secret) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (secret) headers[SIGNATURE_HEADER] = signHmac(secret, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handlePreflight(reqId, secret) {
  return { ok: true, protocolVersion: 'v1' };
}

async function handleTask(reqId, envelope, secret) {
  const taskId = envelope.task_id;
  const input = envelope.input;
  if (!taskId || typeof taskId !== 'string') throw Object.assign(new Error('missing task_id'), { status: 400 });
  if (!input || typeof input !== 'object') throw Object.assign(new Error('missing input'), { status: 400 });

  // 1. Idempotency: a retry returns the exact cached response.
  const cached = store.getCached(taskId);
  if (cached) {
    log({ level: 'info', msg: 'task replay (idempotent)', reqId, taskId });
    return { response: cached, replay: true };
  }

  // 2. Decide (pure, deterministic). Throws on missing/invalid fields.
  const { decision, reasonCode } = decide(input, (tx) => store.isSeen(tx));
  const proofTx = String(input.proof_tx);

  // 3. PROOF_REUSED carries no proof by event rule — answer bare.
  if (reasonCode === 'PROOF_REUSED') {
    const response = { decision, reason_code: reasonCode, proof_tx: proofTx };
    store.markSeen(proofTx);
    store.setCached(taskId, response);
    log({ level: 'info', msg: 'task decided', reqId, taskId, decision, reasonCode, proof: false });
    return { response, replay: false };
  }

  // 4. Generate the Groth16 proof of the decision. On failure, answer
  //    the decision without a proof (still +10 vs -2 timeout) and log.
  let proof = null;
  let publicSignals = null;
  try {
    const circuitInput = buildCircuitInput(taskId, input, decision, randomSalt());
    const generated = await generateProof(circuitInput);
    proof = generated.proof;
    publicSignals = generated.publicSignals;
  } catch (err) {
    log({ level: 'error', msg: 'proof generation failed', reqId, taskId, decision, reasonCode, err: String(err).slice(0, 300) });
  }

  const response = { decision, reason_code: reasonCode, proof_tx: proofTx };
  if (proof && publicSignals) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  store.markSeen(proofTx);
  store.setCached(taskId, response);
  log({ level: 'info', msg: 'task decided', reqId, taskId, decision, reasonCode, proof: Boolean(proof) });

  // 5. Optional async Kurier audit (never blocks the response).
  if (proof && publicSignals) {
    submitProofAudit({ proof, publicSignals, taskId }).catch(() => {});
  }
  return { response, replay: false };
}

const server = http.createServer(async (req, res) => {
  const reqId = randomUUID().slice(0, 8);
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'gatekeeper-agent',
        version: VERSION,
        proof: { configured: true, vkHash: GATEKEEPER_VK_HASH },
        state: store.counts(),
      });
    }
    if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/')) {
      const secret = process.env.AGENT_GAMES_HMAC_SECRET;
      if (!secret) {
        return sendJson(res, 503, { error: 'agent secret not configured' });
      }
      const rawBody = await readBody(req);
      if (!verifyHmac(secret, rawBody, req.headers[SIGNATURE_HEADER])) {
        log({ level: 'warn', msg: 'hmac mismatch', reqId, path: url.pathname });
        return sendJson(res, 401, { error: 'invalid signature' });
      }
      let envelope;
      try {
        envelope = JSON.parse(rawBody.toString('utf8'));
      } catch {
        return sendJson(res, 400, { error: 'invalid JSON' }, secret);
      }
      if (envelope && envelope.type === 'agent-games.preflight.v1') {
        const out = await handlePreflight(reqId, secret);
        log({ level: 'info', msg: 'preflight ok', reqId });
        return sendJson(res, 200, out, secret);
      }
      if (envelope && envelope.type === 'agent-games.proof-gatekeeper.v1') {
        const { response } = await handleTask(reqId, envelope, secret);
        return sendJson(res, 200, response, secret);
      }
      return sendJson(res, 400, { error: 'unknown envelope type' }, secret);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    const status = err.status || 500;
    log({ level: 'error', msg: 'request failed', reqId, err: String(err).slice(0, 300) });
    if (!res.headersSent) sendJson(res, status, { error: status === 400 ? String(err.message) : 'internal error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  log({ level: 'info', msg: 'listening', port: PORT });
});
