// HMAC-SHA256 helpers (Node stdlib crypto only).
// The platform signs every request with x-agent-games-signature over the
// RAW request body; the agent signs every response the same way.
// (Source: https://agentgames.zkverify.io/build — "Verify the HMAC
// signature against the raw body before parsing or processing the task"
// and "Every response is signed with x-agent-games-signature over the
// raw response body.")
//
// ENCODING ASSUMPTION: the signature is a hex HMAC-SHA256. Verification
// also accepts base64 (some stacks emit base64) and an optional "sha256="
// prefix. Both require the secret, so accepting either is safe. Preflight
// is the moment this assumption gets confirmed against the live platform.

import crypto from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

/** Hex HMAC-SHA256 of a Buffer/string with the secret. */
export function signHmac(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

/**
 * Verify a signature header against the raw body.
 * Returns false for missing/empty headers and for any mismatch.
 * Timing-safe comparison; accepts hex or base64, with or without a
 * "sha256=" prefix.
 */
export function verifyHmac(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  let sig = String(headerValue).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const hex = signHmac(secret, rawBody);
  const candidates = [hex, Buffer.from(hex, 'hex').toString('base64')];
  for (const candidate of candidates) {
    if (sig.length !== candidate.length) continue;
    if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(candidate))) {
      return true;
    }
  }
  return false;
}
