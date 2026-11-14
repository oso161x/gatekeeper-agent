// Persistent state: proof_tx seen-set + idempotency cache (task_id -> response).
// Stored as one JSON file under data/ (best-effort: a failed write is
// logged, never fatal — the in-memory copy keeps serving).
//
// RAILWAY EPHEMERAL-FILESYSTEM NOTE: Railway containers have no durable
// local disk across restarts/redeploys, so a restart loses both the
// seen-set and the response cache. What that costs:
//  - Seen-set loss: a proof_tx seen before the restart could be APPROVEd
//    instead of REJECTed as PROOF_REUSED if the platform re-sends it
//    (a wrong APPROVE is -6 instead of +12). PROOF_REUSED tasks are
//    ~11% of tasks, and only repeats that straddle a restart are at risk.
//  - Response-cache loss: a retried task_id is re-decided from its fields
//    (same correct decision, fresh proof with a fresh salt) — harmless.
// Mitigations if this ever bites: a Railway Volume mounted at data/, or
// an external KV. For the 8-round event (8 tasks/day/agent) the exposure
// is small and the file + memory copy is the pragmatic v1.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = path.join(__dirname, '..', 'data');
// Overridable for tests so the suite never touches the live state file.
export const STATE_PATH =
  process.env.GATEKEEPER_STATE_PATH || path.join(DATA_DIR, 'state.json');

export function createStore() {
  let seen = new Set();
  let responses = new Map();
  let loaded = false;

  function load() {
    try {
      const raw = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
      seen = new Set(Array.isArray(raw.seen) ? raw.seen : []);
      responses = new Map(Object.entries(raw.responses || {}));
      loaded = true;
    } catch {
      seen = new Set();
      responses = new Map();
      loaded = false; // first run or unreadable file — start empty
    }
    return { seenCount: seen.size, cachedCount: responses.size, loaded };
  }

  function save() {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const tmp = STATE_PATH + '.tmp';
      fs.writeFileSync(
        tmp,
        JSON.stringify({ seen: [...seen], responses: Object.fromEntries(responses) }),
      );
      fs.renameSync(tmp, STATE_PATH);
    } catch (err) {
      console.error(JSON.stringify({ level: 'error', msg: 'state save failed', err: String(err) }));
    }
  }

  return {
    load,
    save,
    isSeen: (proofTx) => seen.has(String(proofTx)),
    markSeen: (proofTx) => {
      seen.add(String(proofTx));
      save();
    },
    getCached: (taskId) => responses.get(String(taskId)) || null,
    setCached: (taskId, response) => {
      responses.set(String(taskId), response);
      save();
    },
    counts: () => ({ seen: seen.size, cached: responses.size }),
  };
}
