/** Mirrors MAX_CONSOLE_SESSIONS in the backend, which rejects the next connect. */
export const MAX_CONSOLE_SESSIONS = 16;

/** Sessions holding a transport. A disconnected tab costs nothing but scrollback. */
export function countLiveSessions(sessions) {
  return sessions.filter((session) => (
    session.state === 'connected' || session.state === 'connecting'
  )).length;
}

export function defaultSessionName(params) {
  return params.kind === 'serial' ? params.port : params.host;
}

export function canReconnectAfterError(message) {
  return /timed?\s*out|connection.*closed|connection.*reset|broken pipe|disconnected|unexpected eof/i.test(message);
}

/**
 * Splits SSH credentials out of connect params.
 *
 * The sanitized half is what gets stored in React state; the secret half is
 * held separately in a ref that is cleared as soon as a session can no longer
 * need it, so passwords and key material do not sit in component state for the
 * lifetime of the app.
 */
export function splitSecret(params) {
  if (params.kind !== 'ssh') return { safeParams: params, secret: null };
  const { auth, ...rest } = params;
  return { safeParams: { ...rest, auth: { mode: auth.mode } }, secret: auth };
}

/** Rebuilds full connect params from a sanitized copy and its retained secret. */
export function withSecret(safeParams, secret) {
  return secret ? { ...safeParams, auth: secret } : safeParams;
}

/** Whether these params still need a secret that is no longer held. */
export function needsForgottenSecret(safeParams, secret) {
  return safeParams?.kind === 'ssh' && !secret;
}
