// Random values, hashes, HMAC, and base64url helpers. Web Crypto only, which Workers provide.

const SUBDOMAIN_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
// No vowels and no look-alike characters, so a code read off a screen is unambiguous.
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(input: string): Uint8Array {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/** Random token as base64url. 32 bytes is 256 bits. */
export function randomToken(length = 32): string {
  return bytesToBase64Url(randomBytes(length));
}

/** Opaque row id: 16 random bytes as hex. */
export function randomId(): string {
  return bytesToHex(randomBytes(16));
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return bytesToHex(new Uint8Array(digest));
}

/** SHA-256 as base64url, the form PKCE's code_challenge needs. */
export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return bytesToBase64Url(new Uint8Array(digest));
}

/** Rejection sampling: only bytes below the largest multiple of the alphabet size are used, so every character is equally likely. */
function sampleFrom(alphabet: string, count: number): string {
  const limit = 256 - (256 % alphabet.length);
  let out = '';
  while (out.length < count) {
    for (const b of randomBytes(count * 2)) {
      if (b < limit && out.length < count) out += alphabet[b % alphabet.length];
    }
  }
  return out;
}

/** Instance label, e.g. k7x2m9qa4d. Ten characters from [a-z0-9]. */
export function randomSubdomain(): string {
  return sampleFrom(SUBDOMAIN_ALPHABET, 10);
}

/** Code the customer types in the browser, formatted XXXX-XXXX. */
export function randomUserCode(): string {
  const raw = sampleFrom(USER_CODE_ALPHABET, 8);
  return `${raw.slice(0, 4)}-${raw.slice(4)}`;
}

/** Makes typed input comparable: upper case, letters and digits only. */
export function normalizeUserCode(input: string): string {
  return input.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/** Tunnel token, plus the SHA-256 hash that is the only thing stored. */
export async function issueTunnelToken(): Promise<{ token: string; hash: string }> {
  const token = randomToken(32);
  return { token, hash: await sha256Hex(token) };
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export async function hmacSign(secret: string, data: string): Promise<string> {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), new TextEncoder().encode(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

/** Uses crypto.subtle.verify, which compares in constant time. Malformed input returns false. */
export async function hmacVerify(secret: string, data: string, signature: string): Promise<boolean> {
  try {
    return await crypto.subtle.verify('HMAC', await hmacKey(secret), base64UrlToBytes(signature), new TextEncoder().encode(data));
  } catch {
    return false;
  }
}

/** Compares two strings in constant time. Both are hashed first, so the length of the input doesn't leak either. */
export async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = [await sha256Hex(a), await sha256Hex(b)];
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha.charCodeAt(i) ^ hb.charCodeAt(i);
  return diff === 0;
}
