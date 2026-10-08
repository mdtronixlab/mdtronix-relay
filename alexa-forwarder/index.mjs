// AWS Lambda that Alexa's Smart Home skill calls. Alexa only accepts a Lambda endpoint, so this
// function passes each directive to the relay unchanged and returns the relay's answer.
// The relay checks the account token and does the device work (see src/voice.ts and PROTOCOL.md 2.5).
// Deploy in eu-west-1, the region Alexa's Europe/India endpoint uses. Set RELAY_URL to override.

const DEFAULT_RELAY_URL = 'https://relay.mdtronix.online/v1/voice/alexa';
// Alexa gives a Smart Home skill about 8 seconds. Keep room to return an error before that.
const RELAY_TIMEOUT_MS = 6000;

// Alexa error types used here: https://developer.amazon.com/docs/device-apis/alexa-errorresponse.html
const ERRORS = {
  unauthorized: 'INVALID_AUTHORIZATION_CREDENTIAL',
  unreachable: 'ENDPOINT_UNREACHABLE',
  internal: 'INTERNAL_ERROR',
};

function errorResponse(directive, type, message) {
  const header = directive?.header ?? {};
  const responseHeader = {
    namespace: 'Alexa',
    name: 'ErrorResponse',
    payloadVersion: '3',
    messageId: header.messageId ?? crypto.randomUUID(),
  };
  if (header.correlationToken) responseHeader.correlationToken = header.correlationToken;
  const event = { header: responseHeader, payload: { type, message } };
  if (directive?.endpoint?.endpointId) event.endpoint = { endpointId: directive.endpoint.endpointId };
  return { event };
}

/** Maps a relay status to an Alexa error type. Used when the relay doesn't return a usable Alexa response. */
export function errorTypeForStatus(status) {
  if (status === 401) return ERRORS.unauthorized;
  if (status === 503 || status === 504 || status === 402) return ERRORS.unreachable;
  return ERRORS.internal;
}

export async function handler(event, _context, options = {}) {
  const relayUrl = options.relayUrl ?? process.env.RELAY_URL ?? DEFAULT_RELAY_URL;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const directive = event?.directive;

  let response;
  try {
    response = await fetchImpl(relayUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(RELAY_TIMEOUT_MS),
    });
  } catch {
    return errorResponse(directive, ERRORS.unreachable, 'MDtronix could not be reached. Try again in a moment.');
  }

  const text = await response.text();
  if (!response.ok) {
    return errorResponse(directive, errorTypeForStatus(response.status), 'MDtronix could not complete the request.');
  }
  try {
    return JSON.parse(text);
  } catch {
    return errorResponse(directive, ERRORS.internal, 'MDtronix sent an unreadable reply.');
  }
}
