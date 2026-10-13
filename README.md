# mdtronix-relay

Remote access relay for MDtronix customers' Home Assistant instances. It runs on Cloudflare Workers with one Durable Object per instance. It holds the device login, customer email/password sign-in, and the HA tunnel.

Status: the device login, email/password sign-in, approval page, tunnel, and unlink are built and tested locally. Protocol: `docs/remote-access/PROTOCOL.md` in the SmartHome repo. Open items are in `docs/remote-access/PHASE0.md`.

## Setup

```
npm install
npx wrangler d1 create mdtronix-customers   # already created; database_id is in wrangler.jsonc
npm run d1:migrate:local
npm run dev
```

Deploy only after the schema in `migrations/` is reviewed. The Workers Paid plan is needed for Durable Object WebSocket volume.

## Tests

```
npm run typecheck
npm test
```

`npm test` starts a local relay with `wrangler dev` and runs a fake Home Assistant client through the tunnel: link, proxied HTTP and WebSocket, unlink, and relink.

Local note: `wrangler dev` rewrites the `Host` header to the route's domain. The tests therefore send the instance host in `x-mdt-dev-host`. The relay honours that header only when `DEV_LOGIN` is `true`, which is set only for local runs.

Local note: values in `.dev.vars` don't reach the request handlers yet, so the test passes its secrets as `--var` flags. Root cause still open.

## Layout

- `src/index.ts`: host routing. Instance hosts are proxied to their tunnel. Everything else is the relay API.
- `src/tunnel.ts`: tunnel attach, unlink, and public proxying
- `src/tunnel-do.ts`: one Durable Object per instance
- `src/frames.ts`: wire format
- `src/device.ts`, `src/web.ts`, `src/google.ts`, `src/instance.ts`: device login, browser sessions, Google sign-in, and instance rules
- `src/crypto.ts`, `src/http.ts`, `src/env.ts`: helpers
- `migrations/`: `mdtronix-customers` schema
- `tests/tunnel.test.mjs`: end-to-end tunnel test
