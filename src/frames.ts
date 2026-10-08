// Tunnel wire format, from docs/remote-access/PROTOCOL.md section 2.

export const PROTOCOL_VERSION = 1;
export const MAX_STREAMS = 64;
export const MAX_REQUEST_BYTES = 10 * 1024 * 1024;
export const PING_INTERVAL_S = 30;
export const PONG_TIMEOUT_S = 90;
export const RESPONSE_TIMEOUT_MS = 30_000;

export const OP_TEXT = 0x01;
export const OP_BINARY = 0x02;

// Voice fulfillment (PROTOCOL.md section 2.5). Requests are small JSON documents, and Google and
// Alexa expect an answer within a few seconds.
export const VOICE_TIMEOUT_MS = 8_000;
export const MAX_VOICE_REQUEST_BYTES = 64 * 1024;
export const MAX_VOICE_REPLY_BYTES = 256 * 1024;
export const VOICE_PLATFORMS = ['google', 'alexa'] as const;
export type VoicePlatform = (typeof VOICE_PLATFORMS)[number];

export type HeaderMap = Record<string, string | string[]>;

/** Text frames sent by Home Assistant. */
export type HaMessage =
  | { t: 'hello'; v: number; ha_version?: string; client_version?: string; caps?: string[] }
  | { t: 'res'; id: number; status: number; headers: HeaderMap }
  | { t: 'end'; id: number }
  | { t: 'ws_accept'; id: number; protocol?: string }
  | { t: 'ws_close'; id: number; code?: number; reason?: string }
  | { t: 'reset'; id: number; reason?: string }
  | { t: 'voice_res'; id: number; status: number; body: string }
  | { t: 'ping' }
  | { t: 'pong' };

/** Text frames sent by the relay. */
export type RelayMessage =
  | { t: 'ready'; instance: string; max_streams: number }
  | { t: 'req'; id: number; method: string; path: string; query: string; headers: HeaderMap }
  | { t: 'ws_open'; id: number; path: string; query: string; headers: HeaderMap }
  | { t: 'end'; id: number }
  | { t: 'ws_close'; id: number; code?: number; reason?: string }
  | { t: 'reset'; id: number; reason?: string }
  | { t: 'voice'; id: number; platform: VoicePlatform; body: string }
  | { t: 'ping' }
  | { t: 'pong' };

/** Binary frame: 4-byte big-endian stream id, then the payload. */
export function encodeData(id: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + payload.byteLength);
  new DataView(out.buffer).setUint32(0, id, false);
  out.set(payload, 4);
  return out;
}

export function decodeData(buffer: ArrayBuffer): { id: number; payload: Uint8Array } {
  const id = new DataView(buffer).getUint32(0, false);
  return { id, payload: new Uint8Array(buffer, 4) };
}

/** WebSocket message inside a stream: opcode byte, then the message bytes. */
export function encodeWsMessage(id: number, text: boolean, data: Uint8Array): Uint8Array {
  const payload = new Uint8Array(1 + data.byteLength);
  payload[0] = text ? OP_TEXT : OP_BINARY;
  payload.set(data, 1);
  return encodeData(id, payload);
}

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

/** Headers from a browser request, prepared for HA. Drops hop-by-hop headers, the host header, and any X-MDT-* header, and sets the X-Forwarded-* headers itself so clients can't spoof them. */
export function requestHeaders(source: Headers, forwardedFor: string | null, forwardedHost: string): HeaderMap {
  const out: HeaderMap = {};
  source.forEach((value, name) => {
    const key = name.toLowerCase();
    if (HOP_BY_HOP.has(key) || key === 'host' || key.startsWith('x-mdt-') || key.startsWith('x-forwarded-')) return;
    out[key] = value;
  });
  if (forwardedFor) out['x-forwarded-for'] = forwardedFor;
  out['x-forwarded-proto'] = 'https';
  out['x-forwarded-host'] = forwardedHost;
  return out;
}

/** Response headers from HA, ready for the browser response. */
export function responseHeaders(source: HeaderMap): Headers {
  const out = new Headers();
  for (const [name, value] of Object.entries(source)) {
    const key = name.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    for (const v of Array.isArray(value) ? value : [value]) out.append(key, v);
  }
  return out;
}
