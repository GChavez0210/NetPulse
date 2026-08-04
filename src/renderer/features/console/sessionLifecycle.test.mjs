import assert from 'node:assert/strict';
import test from 'node:test';
import { canReconnectAfterError, defaultSessionName } from './sessionLifecycle.mjs';

test('uses the host or physical port as the initial tab name', () => {
  assert.equal(defaultSessionName({ kind: 'ssh', host: '10.0.0.12' }), '10.0.0.12');
  assert.equal(defaultSessionName({ kind: 'serial', port: 'COM7' }), 'COM7');
});

test('offers reconnect only for interrupted connections', () => {
  assert.equal(canReconnectAfterError('Connection timed out.'), true);
  assert.equal(canReconnectAfterError('Console read failed: connection reset by peer'), true);
  assert.equal(canReconnectAfterError('The remote console disconnected.'), true);
  assert.equal(canReconnectAfterError('SSH authentication failed.'), false);
  assert.equal(canReconnectAfterError('Connection refused.'), false);
});
