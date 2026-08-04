import assert from 'node:assert/strict';
import test from 'node:test';
import {
  canReconnectAfterError,
  defaultSessionName,
  needsForgottenSecret,
  splitSecret,
  withSecret,
} from './sessionLifecycle.mjs';

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

test('keeps SSH credentials out of the params retained in state', () => {
  const params = {
    kind: 'ssh',
    host: '10.0.0.12',
    port: 22,
    username: 'admin',
    auth: { mode: 'password', password: 'hunter2' },
    legacy_algos: false,
  };
  const { safeParams, secret } = splitSecret(params);

  assert.deepEqual(safeParams.auth, { mode: 'password' });
  assert.equal(JSON.stringify(safeParams).includes('hunter2'), false);
  assert.equal(secret.password, 'hunter2');
  // Everything needed to describe and rebuild the session survives.
  assert.equal(safeParams.host, '10.0.0.12');
  assert.deepEqual(withSecret(safeParams, secret), params);
});

test('leaves credential-free transports untouched', () => {
  const serial = { kind: 'serial', port: 'COM7', baud: 9600 };
  const { safeParams, secret } = splitSecret(serial);
  assert.equal(secret, null);
  assert.deepEqual(safeParams, serial);
  assert.equal(needsForgottenSecret(safeParams, null), false);
});

test('flags an SSH session whose credentials were already cleared', () => {
  const { safeParams, secret } = splitSecret({
    kind: 'ssh',
    host: '10.0.0.12',
    auth: { mode: 'key', private_key: 'PEM', passphrase: null },
  });
  assert.equal(needsForgottenSecret(safeParams, secret), false);
  assert.equal(needsForgottenSecret(safeParams, undefined), true);
});
