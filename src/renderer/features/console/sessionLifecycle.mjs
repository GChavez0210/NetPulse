export function defaultSessionName(params) {
  return params.kind === 'serial' ? params.port : params.host;
}

export function canReconnectAfterError(message) {
  return /timed?\s*out|connection.*closed|connection.*reset|broken pipe|disconnected|unexpected eof/i.test(message);
}
