// Local Groth16 proof generation with snarkjs (platform circuit artifacts).
//
// The circuit is the platform's gatekeeper circuit (compiled with Circom
// 2.x, Groth16/BN128). Input signals and public-signal layout were
// reverse-engineered from the published wasm/zkey — see circuits/CIRCUIT.md.
//
// NOTE ON DEPENDENCIES: the rest of this agent is Node stdlib-only, but
// local proving needs a Groth16 prover. snarkjs is the platform's own
// documented tool for this ("generate proofs locally with snarkjs"), so it
// is the single declared dependency (package.json). It is loaded lazily via
// createRequire — the ESM `import * as snarkjs` path hangs on this Node
// version (the bundled CJS entry), while require() works and proves in
// ~1s. Proof generation is isolated here so the HTTP/decision layer stays
// stdlib-only.

import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { FIELD_PRIME } from './decide.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
export const WASM_PATH = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
export const ZKEY_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
// vk_hash of the gatekeeper circuit, registered on zkVerify mainnet
// (https://agentgames.zkverify.io/api/circuit-info).
export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

let snarkjsPromise = null;
function loadSnarkjs() {
  if (!snarkjsPromise) {
    snarkjsPromise = Promise.resolve().then(() => {
      const require = createRequire(import.meta.url);
      return require('snarkjs');
    });
  }
  return snarkjsPromise;
}

/** Fresh random salt (private circuit input) — 128 random bits. */
export function randomSalt() {
  return BigInt('0x' + crypto.randomBytes(16).toString('hex'));
}

/**
 * Generate a Groth16 proof for the given circuit inputs.
 * @param {object} circuitInput  13 fields, decimal strings (see decide.mjs)
 * @returns {Promise<{proof: object, publicSignals: string[]}>}
 */
export async function generateProof(circuitInput) {
  const snarkjs = await loadSnarkjs();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  );
  return { proof, publicSignals };
}

/** Locally verify a proof against the exported verification key (tests). */
export async function verifyProofLocally(proof, publicSignals) {
  const snarkjs = await loadSnarkjs();
  const { readFileSync } = await import('node:fs');
  const vk = JSON.parse(
    readFileSync(path.join(CIRCUITS_DIR, 'vk.json'), 'utf8'),
  );
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

export { FIELD_PRIME };
