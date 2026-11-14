// Optional async audit: submit a generated proof to zkVerify via Kurier
// (mainnet) and poll until Finalized. This is NOT on the response path:
// the platform re-verifies the proof itself, and a Kurier round-trip
// (~2-6 min) cannot fit the 60s task deadline, so this runs in the
// background after the response is sent and never blocks a decision.
// It is skipped entirely when KURIER_API_KEY is unset.
//
// Kurier mainnet needs a MAINNET API key (https://api.kurier.xyz).
// The testnet key from the Transfer Guard project does NOT work here.

import { GATEKEEPER_VK_HASH } from './prove.mjs';

const KURIER_API_URL = 'https://api.kurier.xyz/api/v1';
const POLL_INTERVAL_MS = 15_000;
const POLL_TIMEOUT_MS = 300_000;

function log(obj) {
  console.error(JSON.stringify({ ...obj, scope: 'kurier' }));
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep raw text */ }
  if (!res.ok) throw new Error(`Kurier ${res.status}: ${text.slice(0, 200)}`);
  return json;
}

async function getJson(url) {
  const res = await fetch(url);
  const text = await res.text();
  if (!res.ok) throw new Error(`Kurier ${res.status}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

/** Fire-and-forget: submit + poll, log the outcome, never throw. */
export async function submitProofAudit({ proof, publicSignals, taskId }) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) return { skipped: true, reason: 'KURIER_API_KEY unset' };
  try {
    const submitted = await postJson(
      `${KURIER_API_URL}/submit-proof/${apiKey}`,
      {
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
      },
    );
    const jobId = submitted.jobId || submitted.job_id || submitted.id;
    if (!jobId) {
      log({ level: 'warn', msg: 'kurier submit: no jobId', taskId });
      return { submitted: false };
    }
    const started = Date.now();
    while (Date.now() - started < POLL_TIMEOUT_MS) {
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
      const status = await getJson(
        `${KURIER_API_URL}/job-status/${apiKey}/${jobId}`,
      );
      const state = status.status || status.state || status.jobStatus;
      if (state === 'Finalized') {
        log({ level: 'info', msg: 'kurier proof Finalized', taskId, jobId });
        return { submitted: true, jobId, status: 'Finalized' };
      }
      if (state === 'Failed' || state === 'Invalid') {
        log({ level: 'warn', msg: 'kurier proof failed', taskId, jobId, state });
        return { submitted: true, jobId, status: state };
      }
    }
    log({ level: 'warn', msg: 'kurier poll timed out', taskId, jobId });
    return { submitted: true, jobId, status: 'poll-timeout' };
  } catch (err) {
    log({ level: 'warn', msg: 'kurier audit failed', taskId, err: String(err).slice(0, 200) });
    return { submitted: false, error: String(err).slice(0, 200) };
  }
}
