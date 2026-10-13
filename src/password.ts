// Password hashing for customer accounts. Web Crypto only (PBKDF2), matching the rest of the codebase:
// no npm crypto deps, since this runs in the Workers runtime.

import { randomBytes, bytesToBase64Url, base64UrlToBytes } from './crypto';

// Cloudflare Workers' PBKDF2 implementation caps iterations at 100,000 (crypto.subtle.deriveBits throws
// above that, unlike a browser) — confirmed in production: "Pbkdf2 failed: iteration counts above 100000
// are not supported". 100,000 is still the long-standing OWASP baseline, just not their newer 210,000
// recommendation, which Workers can't do.
const ITERATIONS = 100_000;
const SALT_BYTES = 16;
const HASH_BITS = 256;

async function deriveBits(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, HASH_BITS);
  return new Uint8Array(bits);
}

/** Stored as pbkdf2$<iterations>$<saltB64url>$<hashB64url>, so the iteration count can rise later without breaking old hashes. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await deriveBits(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${bytesToBase64Url(salt)}$${bytesToBase64Url(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations <= 0) return false;

  try {
    const salt = base64UrlToBytes(parts[2]);
    const expected = base64UrlToBytes(parts[3]);
    const actual = await deriveBits(password, salt, iterations);
    if (actual.length !== expected.length) return false;
    // Constant-time compare: a length mismatch already returned above, so this loop's time only
    // depends on the (fixed) hash length, not on where the first differing byte is.
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch {
    return false;
  }
}
