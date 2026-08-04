import React, { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

const SERIAL_BAUD_RATES = [9600, 19200, 38400, 57600, 115200];

function Field({ label, children }) {
  return (
    <label className="console-field">
      <span>{label}</span>
      {children}
    </label>
  );
}

export default function ConnectForm({
  transport,
  onTransportChange,
  connectionState,
  onConnect,
  onFormMessage,
  hasSessions = false,
  sessionLimitReached = false,
  collapsed = false,
  onToggleCollapsed,
}) {
  const [advancedSerial, setAdvancedSerial] = useState(false);
  const [host, setHost] = useState('');
  const [sshPort, setSshPort] = useState('22');
  const [telnetPort, setTelnetPort] = useState('23');
  const [username, setUsername] = useState('');
  const [authMode, setAuthMode] = useState('password');
  const [password, setPassword] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [legacyAlgos, setLegacyAlgos] = useState(false);
  const [serialPorts, setSerialPorts] = useState([]);
  const [serialPort, setSerialPort] = useState('');
  const [baud, setBaud] = useState('9600');
  const [dataBits, setDataBits] = useState('8');
  const [parity, setParity] = useState('none');
  const [stopBits, setStopBits] = useState('1');
  const [flowControl, setFlowControl] = useState('none');
  const [localEcho, setLocalEcho] = useState(false);
  const [loadingPorts, setLoadingPorts] = useState(false);
  const busy = connectionState !== 'disconnected';
  const formDisabled = busy || sessionLimitReached;

  const refreshPorts = useCallback(async () => {
    setLoadingPorts(true);
    if (!window.__TAURI_INTERNALS__) {
      setSerialPorts([]);
      setSerialPort('');
      setLoadingPorts(false);
      onFormMessage?.('Serial port discovery is available in the NetPulse desktop app.');
      return;
    }
    try {
      const ports = await invoke('serial_list_ports');
      setSerialPorts(ports);
      setSerialPort((current) => (
        ports.some((port) => port.path === current) ? current : (ports[0]?.path ?? '')
      ));
      onFormMessage?.(ports.length ? '' : 'No serial ports were found. Plug in an adapter and refresh.');
    } catch (error) {
      onFormMessage?.(String(error));
    } finally {
      setLoadingPorts(false);
    }
  }, [onFormMessage]);

  useEffect(() => {
    if (transport === 'serial') refreshPorts();
  }, [refreshPorts, transport]);

  const submit = (event) => {
    event.preventDefault();
    if (formDisabled) return;

    // The port field is plain text now, so the range it used to get from the
    // number input's min/max is checked here instead.
    if (transport !== 'serial') {
      const port = Number(transport === 'ssh' ? sshPort : telnetPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        onFormMessage?.('TCP port must be a number between 1 and 65535.');
        return;
      }
    }

    if (transport === 'ssh') {
      const auth = authMode === 'password'
        ? { mode: 'password', password }
        : { mode: 'key', private_key: privateKey, passphrase: passphrase || null };
      onConnect({
        kind: 'ssh',
        host: host.trim(),
        port: Number(sshPort),
        username: username.trim(),
        auth,
        legacy_algos: legacyAlgos,
      }, { localEcho: false });
      return;
    }

    if (transport === 'telnet') {
      onConnect({ kind: 'telnet', host: host.trim(), port: Number(telnetPort) }, { localEcho: false });
      return;
    }

    onConnect({
      kind: 'serial',
      port: serialPort,
      baud: Number(baud),
      data_bits: Number(dataBits),
      parity,
      stop_bits: Number(stopBits),
      flow_control: flowControl,
    }, { localEcho });
  };

  return (
    <form className={`diag-card console-connect-card ${collapsed ? 'collapsed' : ''}`} onSubmit={submit}>
      <div className="console-connect-heading">
        <div>
          <span>CONNECTION DETAILS</span>
          <small>{collapsed ? `${transport.toUpperCase()} settings hidden to maximize terminal space` : 'Configure a new SSH, Telnet, or serial session'}</small>
        </div>
        <button
          type="button"
          className="secondary console-collapse-button"
          aria-expanded={!collapsed}
          aria-controls="console-connection-fields"
          onClick={onToggleCollapsed}
        >
          {collapsed ? 'Expand' : 'Collapse'}
        </button>
      </div>

      <div id="console-connection-fields" className="console-connection-fields" hidden={collapsed}>
        <fieldset className="console-form-fieldset" disabled={formDisabled}>
        <div className="console-form-grid">
          <Field label="Transport">
            <select value={transport} onChange={(event) => onTransportChange(event.target.value)}>
              <option value="ssh">SSH</option>
              <option value="telnet">Telnet</option>
              <option value="serial">Serial</option>
            </select>
          </Field>

          {transport === 'serial' ? (
            <>
              <Field label="Port">
                <div className="console-inline-control">
                  <select
                    aria-label="Serial port"
                    value={serialPort}
                    onChange={(event) => setSerialPort(event.target.value)}
                    required
                  >
                    {!serialPorts.length && <option value="">No ports found</option>}
                    {serialPorts.map((port) => <option key={port.path} value={port.path}>{port.label}</option>)}
                  </select>
                  <button type="button" className="secondary" onClick={refreshPorts} disabled={loadingPorts}>
                    {loadingPorts ? 'Scanning…' : 'Refresh'}
                  </button>
                </div>
              </Field>
              <Field label="Baud rate">
                <select value={baud} onChange={(event) => setBaud(event.target.value)}>
                  {SERIAL_BAUD_RATES.map((rate) => <option key={rate} value={rate}>{rate}</option>)}
                </select>
              </Field>
            </>
          ) : (
            <>
              <Field label="Host / IP">
                <input value={host} onChange={(event) => setHost(event.target.value)} placeholder="switch.example.com" autoComplete="off" required />
              </Field>
              <Field label="TCP port">
                <input
                  type="text"
                  inputMode="numeric"
                  // A spinner earns its space on a value you step through. Nobody
                  // walks from 22 to 2001; they type the port they were given.
                  maxLength={5}
                  value={transport === 'ssh' ? sshPort : telnetPort}
                  onChange={(event) => {
                    const digits = event.target.value.replace(/\D/g, '').slice(0, 5);
                    if (transport === 'ssh') setSshPort(digits);
                    else setTelnetPort(digits);
                  }}
                  required
                />
              </Field>
              {transport === 'ssh' && (
                <>
                  <Field label="Username">
                    <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" placeholder="admin" required />
                  </Field>
                  <Field label="Authentication">
                    <select value={authMode} onChange={(event) => setAuthMode(event.target.value)}>
                      <option value="password">Password</option>
                      <option value="key">OpenSSH private key</option>
                    </select>
                  </Field>
                  {authMode === 'password' ? (
                    <Field label="Password">
                      <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" placeholder="never saved" />
                    </Field>
                  ) : (
                    <>
                      <Field label="Private key">
                        <textarea value={privateKey} onChange={(event) => setPrivateKey(event.target.value)} rows="3" placeholder="Paste an OpenSSH private key" required />
                      </Field>
                      <Field label="Key passphrase">
                        <input value={passphrase} onChange={(event) => setPassphrase(event.target.value)} type="password" autoComplete="off" placeholder="If encrypted" />
                      </Field>
                    </>
                  )}
                </>
              )}
            </>
          )}
        </div>

        {transport === 'ssh' && (
          <label className="console-check-row">
            <input type="checkbox" checked={legacyAlgos} onChange={(event) => setLegacyAlgos(event.target.checked)} />
            <span>Allow legacy SSH algorithms <small>Only for older network equipment; weakens connection security.</small></span>
          </label>
        )}

        {transport === 'telnet' && (
          <p className="console-warning">Telnet sends all traffic, including credentials, in cleartext.</p>
        )}

        {transport === 'serial' && (
          <>
            <label className="console-check-row">
              <input type="checkbox" checked={localEcho} onChange={(event) => setLocalEcho(event.target.checked)} />
              <span>Local echo <small>Show typed characters when the attached device does not echo them.</small></span>
            </label>
            <button
              type="button"
              className="console-disclosure"
              aria-expanded={advancedSerial}
              onClick={() => setAdvancedSerial((value) => !value)}
            >
              {advancedSerial ? 'Hide' : 'Show'} advanced serial settings
            </button>
            {advancedSerial && (
              <div className="console-form-grid console-serial-advanced">
                <Field label="Data bits"><select value={dataBits} onChange={(event) => setDataBits(event.target.value)}><option value="8">8</option><option value="7">7</option></select></Field>
                <Field label="Parity"><select value={parity} onChange={(event) => setParity(event.target.value)}><option value="none">None</option><option value="odd">Odd</option><option value="even">Even</option></select></Field>
                <Field label="Stop bits"><select value={stopBits} onChange={(event) => setStopBits(event.target.value)}><option value="1">1</option><option value="2">2</option></select></Field>
                <Field label="Flow control"><select value={flowControl} onChange={(event) => setFlowControl(event.target.value)}><option value="none">None</option><option value="software">Software</option><option value="hardware">Hardware</option></select></Field>
              </div>
            )}
          </>
        )}
        </fieldset>

        <div className="console-connect-actions">
          <p>Credentials stay in memory only and are never saved to settings.</p>
          <button type="submit" disabled={formDisabled}>
            {sessionLimitReached
              ? 'Session limit reached'
              : (connectionState === 'connecting'
              ? 'Connecting…'
              : (hasSessions ? 'Connect another' : 'Connect'))}
          </button>
        </div>
      </div>
    </form>
  );
}
