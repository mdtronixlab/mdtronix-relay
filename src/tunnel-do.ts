// One Durable Object per customer instance. Holds the HA tunnel WebSocket and proxies
// browser requests through it. Wire format: src/frames.ts. Spec: PROTOCOL.md section 2.
//
// Internal paths, only reachable from the Worker (src/index.ts):
//   /__attach  upgrade: Home Assistant connects its tunnel here
//   /__close   POST: close the tunnel (token revoked or unlinked)
//   /__proxy/* any path: forwarded to Home Assistant
//
// The HA socket uses the WebSocket hibernation API, so an idle tunnel doesn't keep the
// Durable Object in memory. Browser WebSockets are accepted normally, and stay in memory
// while open. In-flight streams live in memory, and an in-flight request keeps the object awake.

import { instanceHasAccess } from './billing';
import type { Env } from './env';
import {
  decodeData,
  encodeData,
  encodeWsMessage,
  MAX_REQUEST_BYTES,
  MAX_STREAMS,
  OP_BINARY,
  OP_TEXT,
  PING_INTERVAL_S,
  PONG_TIMEOUT_S,
  PROTOCOL_VERSION,
  RESPONSE_TIMEOUT_MS,
  requestHeaders,
  responseHeaders,
  type HaMessage,
  type HeaderMap,
  type RelayMessage,
} from './frames';

interface HttpStream {
  kind: 'http';
  resolveHead: (response: Response) => void;
  rejectHead: (reason: string) => void;
  controller?: ReadableStreamDefaultController<Uint8Array>;
}

interface WsStream {
  kind: 'ws';
  browser: WebSocket;
  ready: boolean;
  resolveAccept: () => void;
  rejectAccept: (reason: string) => void;
  pending: Array<{ text: boolean; data: Uint8Array }>;
}

type Stream = HttpStream | WsStream;

const HA_TAG = 'ha';
// Re-check the subscription this often while the tunnel is up, so a suspension takes effect within minutes.
const ACCESS_CHECK_INTERVAL_MS = 5 * 60 * 1000;
const TEXT_DECODER = new TextDecoder();
const TEXT_ENCODER = new TextEncoder();

export class TunnelDO {
  private streams = new Map<number, Stream>();
  private nextId = 1;

  constructor(
    private state: DurableObjectState,
    private env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/__attach') return this.attach(request);
    if (url.pathname === '/__close') return this.closeTunnel('revoked');
    if (url.pathname.startsWith('/__proxy')) {
      const path = url.pathname.slice('/__proxy'.length) || '/';
      return this.proxy(request, path, url.search);
    }
    return new Response('not found', { status: 404 });
  }

  // HA side ----------------------------------------------------------------

  private haSocket(): WebSocket | null {
    return this.state.getWebSockets(HA_TAG)[0] ?? null;
  }

  private async attach(request: Request): Promise<Response> {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('expected websocket', { status: 426 });
    }
    const instance = request.headers.get('x-mdt-instance') ?? '';

    // A new connection replaces any old one for this instance.
    for (const old of this.state.getWebSockets(HA_TAG)) old.close(4001, 'replaced');

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server, [HA_TAG]);
    await this.state.storage.put({ instance, lastPongAt: Date.now(), lastAccessCheckAt: Date.now() });
    await this.state.storage.setAlarm(Date.now() + PING_INTERVAL_S * 1000);

    return new Response(null, { status: 101, webSocket: client });
  }

  private closeTunnel(reason: string): Response {
    const ha = this.haSocket();
    if (ha) ha.close(4001, reason);
    return new Response('ok');
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message === 'string') {
      let msg: HaMessage;
      try {
        msg = JSON.parse(message) as HaMessage;
      } catch {
        ws.close(4000, 'invalid json');
        return;
      }
      await this.onControl(ws, msg);
      return;
    }
    this.onData(message);
  }

  async webSocketClose(_ws: WebSocket): Promise<void> {
    // Fail every stream, since HA can't answer them now.
    for (const [id, stream] of this.streams) this.failStream(id, stream, 'home assistant disconnected');
    this.streams.clear();
  }

  async webSocketError(_ws: WebSocket): Promise<void> {
    await this.webSocketClose(_ws);
  }

  private async onControl(ws: WebSocket, msg: HaMessage): Promise<void> {
    switch (msg.t) {
      case 'hello': {
        if (msg.v !== PROTOCOL_VERSION) {
          ws.close(4002, 'unsupported protocol');
          return;
        }
        const instance = (await this.state.storage.get<string>('instance')) ?? '';
        const ready: RelayMessage = { t: 'ready', instance, max_streams: MAX_STREAMS };
        ws.send(JSON.stringify(ready));
        return;
      }
      case 'ping':
        ws.send(JSON.stringify({ t: 'pong' } satisfies RelayMessage));
        return;
      case 'pong':
        await this.state.storage.put('lastPongAt', Date.now());
        return;
      case 'res': {
        const stream = this.streams.get(msg.id);
        if (!stream || stream.kind !== 'http') return;
        const body = new ReadableStream<Uint8Array>({
          start: (controller) => {
            stream.controller = controller;
          },
          cancel: () => {
            // The browser went away. Tell HA to stop sending.
            this.streams.delete(msg.id);
            this.haSocket()?.send(JSON.stringify({ t: 'reset', id: msg.id, reason: 'client cancelled' } satisfies RelayMessage));
          },
        });
        stream.resolveHead(new Response(body, { status: msg.status, headers: responseHeaders(msg.headers) }));
        return;
      }
      case 'end': {
        const stream = this.streams.get(msg.id);
        if (stream?.kind === 'http') {
          stream.controller?.close();
          this.streams.delete(msg.id);
        }
        return;
      }
      case 'ws_accept': {
        const stream = this.streams.get(msg.id);
        if (stream?.kind === 'ws') stream.resolveAccept();
        return;
      }
      case 'ws_close': {
        const stream = this.streams.get(msg.id);
        if (stream?.kind === 'ws') {
          stream.browser.close(msg.code ?? 1000, msg.reason ?? '');
          this.streams.delete(msg.id);
        }
        return;
      }
      case 'reset': {
        const stream = this.streams.get(msg.id);
        if (stream) this.failStream(msg.id, stream, msg.reason ?? 'reset by home assistant');
        this.streams.delete(msg.id);
        return;
      }
    }
  }

  private onData(buffer: ArrayBuffer): void {
    const { id, payload } = decodeData(buffer);
    const stream = this.streams.get(id);
    if (!stream) return;

    if (stream.kind === 'http') {
      stream.controller?.enqueue(payload);
      return;
    }
    if (payload.byteLength === 0) return;
    const text = payload[0] === OP_TEXT;
    const data = payload.subarray(1);
    if (payload[0] !== OP_TEXT && payload[0] !== OP_BINARY) return;
    if (text) stream.browser.send(TEXT_DECODER.decode(data));
    else stream.browser.send(data);
  }

  private failStream(id: number, stream: Stream, reason: string): void {
    if (stream.kind === 'http') {
      if (stream.controller) stream.controller.error(new Error(reason));
      else stream.rejectHead(reason);
    } else {
      if (!stream.ready) stream.rejectAccept(reason);
      stream.browser.close(1011, reason.slice(0, 120));
    }
    void id;
  }

  /** Keepalive. The runtime calls this on the alarm set at attach time. */
  async alarm(): Promise<void> {
    const ha = this.haSocket();
    if (!ha) return;
    const lastPongAt = (await this.state.storage.get<number>('lastPongAt')) ?? 0;
    if (Date.now() - lastPongAt > PONG_TIMEOUT_S * 1000) {
      ha.close(4003, 'ping timeout');
      return;
    }
    const now = Date.now();
    const lastAccessCheckAt = (await this.state.storage.get<number>('lastAccessCheckAt')) ?? 0;
    if (now - lastAccessCheckAt > ACCESS_CHECK_INTERVAL_MS) {
      const instance = (await this.state.storage.get<string>('instance')) ?? '';
      if (!(await instanceHasAccess(this.env.CUSTOMERS, instance))) {
        ha.close(4003, 'subscription inactive');
        return;
      }
      await this.state.storage.put('lastAccessCheckAt', now);
    }

    ha.send(JSON.stringify({ t: 'ping' } satisfies RelayMessage));
    await this.state.storage.setAlarm(Date.now() + PING_INTERVAL_S * 1000);
  }

  // Browser side ------------------------------------------------------------

  private allocId(): number {
    const id = this.nextId;
    this.nextId = this.nextId >= 0xfffffffe ? 1 : this.nextId + 1;
    return id;
  }

  private async proxy(request: Request, path: string, query: string): Promise<Response> {
    const ha = this.haSocket();
    if (!ha) return new Response('Home Assistant is offline.', { status: 503 });
    if (this.streams.size >= MAX_STREAMS) return new Response('Too many requests.', { status: 503 });

    const id = this.allocId();
    const forwardedFor = request.headers.get('cf-connecting-ip');
    const forwardedHost = request.headers.get('host') ?? '';
    const headers = requestHeaders(request.headers, forwardedFor, forwardedHost);

    if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
      return this.proxyWebSocket(ha, id, path, query, headers);
    }
    return this.proxyHttp(ha, id, request, path, query, headers);
  }

  private async proxyHttp(
    ha: WebSocket,
    id: number,
    request: Request,
    path: string,
    query: string,
    headers: HeaderMap,
  ): Promise<Response> {
    let resolveHead!: (response: Response) => void;
    let rejectHead!: (reason: string) => void;
    const head = new Promise<Response>((resolve, reject) => {
      resolveHead = resolve;
      rejectHead = (reason) => reject(new Error(reason));
    });
    const stream: HttpStream = { kind: 'http', resolveHead, rejectHead };
    this.streams.set(id, stream);

    ha.send(JSON.stringify({ t: 'req', id, method: request.method, path, query, headers } satisfies RelayMessage));

    if (request.body) {
      const reader = request.body.getReader();
      let total = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > MAX_REQUEST_BYTES) {
            this.abortStream(id, ha, 'request too large');
            return new Response('Request too large.', { status: 413 });
          }
          ha.send(encodeData(id, value));
        }
      } catch {
        this.abortStream(id, ha, 'client aborted');
        return new Response('Request aborted.', { status: 499 });
      }
    }
    ha.send(JSON.stringify({ t: 'end', id } satisfies RelayMessage));

    try {
      return await withTimeout(head, RESPONSE_TIMEOUT_MS);
    } catch {
      this.abortStream(id, ha, 'timed out');
      return new Response('Home Assistant did not respond in time.', { status: 504 });
    }
  }

  private abortStream(id: number, ha: WebSocket, reason: string): void {
    this.streams.delete(id);
    ha.send(JSON.stringify({ t: 'reset', id, reason } satisfies RelayMessage));
  }

  private async proxyWebSocket(
    ha: WebSocket,
    id: number,
    path: string,
    query: string,
    headers: HeaderMap,
  ): Promise<Response> {
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    let resolveAccept!: () => void;
    let rejectAccept!: (reason: string) => void;
    const accepted = new Promise<void>((resolve, reject) => {
      resolveAccept = resolve;
      rejectAccept = (reason) => reject(new Error(reason));
    });
    const stream: WsStream = {
      kind: 'ws',
      browser: server,
      ready: false,
      resolveAccept,
      rejectAccept,
      pending: [],
    };
    this.streams.set(id, stream);

    const forward = (text: boolean, data: Uint8Array) => {
      const live = this.haSocket();
      if (live) live.send(encodeWsMessage(id, text, data));
    };
    server.addEventListener('message', (event) => {
      if (!stream.ready) {
        if (typeof event.data === 'string') stream.pending.push({ text: true, data: TEXT_ENCODER.encode(event.data) });
        else stream.pending.push({ text: false, data: new Uint8Array(event.data as ArrayBuffer) });
        return;
      }
      if (typeof event.data === 'string') forward(true, TEXT_ENCODER.encode(event.data));
      else forward(false, new Uint8Array(event.data as ArrayBuffer));
    });
    server.addEventListener('close', (event) => {
      this.haSocket()?.send(
        JSON.stringify({ t: 'ws_close', id, code: event.code, reason: event.reason } satisfies RelayMessage),
      );
      this.streams.delete(id);
    });

    ha.send(JSON.stringify({ t: 'ws_open', id, path, query, headers } satisfies RelayMessage));

    try {
      await withTimeout(accepted, RESPONSE_TIMEOUT_MS);
    } catch {
      this.streams.delete(id);
      server.close(1011, 'home assistant did not accept');
      return new Response('Home Assistant did not accept the connection.', { status: 502 });
    }

    stream.ready = true;
    for (const m of stream.pending) forward(m.text, m.data);
    stream.pending = [];
    return new Response(null, { status: 101, webSocket: client });
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}
