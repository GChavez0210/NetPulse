import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Channel, invoke } from '@tauri-apps/api/core';
import ConnectForm from './ConnectForm';
import HostKeyPrompt from './HostKeyPrompt';
import SessionTabs from './SessionTabs';
import TerminalPane from './TerminalPane';
import {
  canReconnectAfterError,
  defaultSessionName,
  needsForgottenSecret,
  splitSecret,
  withSecret,
} from './sessionLifecycle.mjs';

const encoder = new TextEncoder();

function bytesToBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(encoded) {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function eventLevel(state) {
  return {
    connected: 'normal',
    connecting: 'running',
    danger: 'down',
    warning: 'degraded',
  }[state] ?? 'running';
}

export default function ConsoleTab({ isActive }) {
  const [transport, setTransport] = useState('ssh');
  const [sessions, setSessions] = useState([]);
  const [activeKey, setActiveKey] = useState(null);
  const [connecting, setConnecting] = useState(false);
  const [connectFormCollapsed, setConnectFormCollapsed] = useState(false);
  const [connectFormKey, setConnectFormKey] = useState(0);
  const [formStatus, setFormStatus] = useState({ level: 'idle', message: 'Ready for a new connection' });
  const [hostKey, setHostKey] = useState(null);
  const [trustingKey, setTrustingKey] = useState(false);
  const sessionsRef = useRef([]);
  const terminalRefs = useRef(new Map());
  const queuedEvents = useRef(new Map());
  const nextClientKey = useRef(1);
  const pendingConnectRef = useRef(null);
  const hostKeyRef = useRef(null);
  // SSH credentials live here rather than in session state, and only for as
  // long as a session could still need them to reconnect.
  const secretsRef = useRef(new Map());

  useEffect(() => {
    sessionsRef.current = sessions;
  }, [sessions]);

  useEffect(() => {
    const secrets = secretsRef.current;
    return () => {
      sessionsRef.current.forEach((session) => {
        if (session.id) invoke('console_disconnect', { sessionId: session.id }).catch(() => {});
      });
      secrets.clear();
    };
  }, []);

  const updateSession = useCallback((key, changes) => {
    setSessions((current) => current.map((session) => (
      session.key === key ? { ...session, ...changes } : session
    )));
  }, []);

  const writeToTerminal = useCallback((key, action) => {
    const terminal = terminalRefs.current.get(key);
    if (terminal) {
      action(terminal);
      return;
    }
    const queue = queuedEvents.current.get(key) ?? [];
    queue.push(action);
    queuedEvents.current.set(key, queue);
  }, []);

  const setTerminalRef = useCallback((key, terminal) => {
    if (!terminal) {
      terminalRefs.current.delete(key);
      return;
    }
    terminalRefs.current.set(key, terminal);
    const queue = queuedEvents.current.get(key) ?? [];
    queue.forEach((action) => action(terminal));
    queuedEvents.current.delete(key);
  }, []);

  const handleConsoleEvent = useCallback((key, event) => {
    if (event.type === 'data') {
      writeToTerminal(key, (terminal) => terminal.write(base64ToBytes(event.b64)));
      return;
    }
    if (event.type === 'status') {
      updateSession(key, {
        status: { level: eventLevel(event.state), message: event.message },
      });
      return;
    }
    if (event.type === 'hostKey') {
      const prompt = { ...event, keyB64: event.keyB64 ?? event.key_b64, sessionKey: key };
      hostKeyRef.current = prompt;
      updateSession(key, {
        state: 'awaitingTrust',
        status: { level: 'degraded', message: 'SSH host identity needs confirmation' },
      });
      return;
    }
    if (event.type === 'closed') {
      // A clean logout is not a fault and is not worth offering a reconnect
      // for; the backend distinguishes it from a connection that dropped.
      const recoverable = Boolean(event.recoverable);
      if (!recoverable) secretsRef.current.delete(key);
      updateSession(key, {
        id: null,
        state: recoverable ? 'interrupted' : 'closed',
        canReconnect: recoverable,
        status: { level: recoverable ? 'down' : 'idle', message: event.reason },
      });
      writeToTerminal(key, (terminal) => terminal.writeln(
        recoverable ? `\r\n\x1b[31m${event.reason}\x1b[0m` : `\r\n\x1b[2m${event.reason}\x1b[0m`,
      ));
    }
  }, [updateSession, writeToTerminal]);

  const connect = useCallback(async (params, options = {}, existingKey = null) => {
    const key = existingKey ?? `client-${nextClientKey.current++}`;
    const shouldClearForm = existingKey === null
      || sessionsRef.current.find((session) => session.key === existingKey)?.state === 'awaitingTrust';
    const initialStatus = { level: 'running', message: `Connecting via ${params.kind.toUpperCase()}…` };

    // Credentials go to the ref, never into session state or the pending-connect
    // record. `params` itself stays a local and is released with this call.
    const { safeParams, secret } = splitSecret(params);
    if (secret) secretsRef.current.set(key, secret);

    pendingConnectRef.current = { key, params: safeParams, options };
    hostKeyRef.current = null;
    setHostKey(null);
    setConnecting(true);
    setActiveKey(key);

    if (existingKey) {
      updateSession(key, {
        state: 'connecting',
        status: initialStatus,
        canReconnect: false,
        params: safeParams,
        options,
      });
      writeToTerminal(key, (terminal) => terminal.writeln(`\r\n\x1b[2mReconnecting via ${params.kind.toUpperCase()}…\x1b[0m`));
    } else {
      setSessions((current) => [...current, {
        key,
        id: null,
        name: defaultSessionName(safeParams),
        kind: safeParams.kind,
        localEcho: Boolean(options.localEcho),
        params: safeParams,
        options,
        canReconnect: false,
        state: 'connecting',
        status: initialStatus,
        channel: null,
      }]);
    }

    const activeTerminal = terminalRefs.current.get(key)
      ?? terminalRefs.current.get(activeKey);
    const { cols, rows } = activeTerminal?.getSize() ?? { cols: 80, rows: 24 };

    try {
      const channel = new Channel();
      channel.onmessage = (event) => handleConsoleEvent(key, event);
      updateSession(key, { channel });
      const sessionId = await invoke('console_connect', {
        params,
        cols,
        rows,
        onEvent: channel,
      });
      updateSession(key, {
        id: sessionId,
        state: 'connected',
        canReconnect: false,
        status: { level: 'normal', message: `Connected via ${params.kind.toUpperCase()}` },
        channel,
      });
      if (shouldClearForm) {
        setConnectFormKey((current) => current + 1);
        setFormStatus({ level: 'idle', message: 'Ready for a new connection' });
      }
      setConnectFormCollapsed(true);
      writeToTerminal(key, (terminal) => {
        terminal.writeln('\x1b[32mConnected.\x1b[0m');
        terminal.focus();
      });

      if (params.kind === 'serial') {
        writeToTerminal(key, (terminal) => terminal.writeln('\x1b[2mSerial consoles may stay quiet until Enter is pressed. Sending CR…\x1b[0m'));
        await invoke('console_send', { sessionId, b64: bytesToBase64(encoder.encode('\r')) });
      }
      pendingConnectRef.current = null;
    } catch (error) {
      if (hostKeyRef.current?.sessionKey === key) {
        // The retry after trusting the key still needs this record.
        setHostKey(hostKeyRef.current);
      } else {
        pendingConnectRef.current = null;
        const message = String(error);
        const reconnectable = canReconnectAfterError(message);
        updateSession(key, {
          id: null,
          state: reconnectable ? 'interrupted' : 'closed',
          canReconnect: reconnectable,
          status: { level: 'down', message },
        });
        writeToTerminal(key, (terminal) => terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`));
      }
    } finally {
      setConnecting(false);
    }
  }, [activeKey, handleConsoleEvent, updateSession, writeToTerminal]);

  const reconnect = useCallback((key) => {
    const session = sessionsRef.current.find((candidate) => candidate.key === key);
    if (!session?.canReconnect || !session.params) return;
    const secret = secretsRef.current.get(key);
    if (needsForgottenSecret(session.params, secret)) {
      updateSession(key, {
        canReconnect: false,
        status: { level: 'degraded', message: 'Credentials were cleared. Reconnect from the connection form.' },
      });
      return;
    }
    connect(withSecret(session.params, secret), session.options ?? {}, key);
  }, [connect, updateSession]);

  const disconnect = useCallback(async (key) => {
    const session = sessionsRef.current.find((candidate) => candidate.key === key);
    if (!session?.id) return;
    // A deliberate disconnect ends the session, so its credentials are no
    // longer needed; a later reconnect goes back through the form.
    secretsRef.current.delete(key);
    updateSession(key, {
      id: null,
      state: 'disconnected',
      canReconnect: false,
      status: { level: 'idle', message: 'Disconnected' },
    });
    try {
      await invoke('console_disconnect', { sessionId: session.id });
      writeToTerminal(key, (terminal) => terminal.writeln('\r\n\x1b[2mDisconnected.\x1b[0m'));
    } catch (error) {
      updateSession(key, { status: { level: 'down', message: String(error) } });
    }
  }, [updateSession, writeToTerminal]);

  const closeSession = useCallback(async (key) => {
    const snapshot = sessionsRef.current;
    const session = snapshot.find((candidate) => candidate.key === key);
    if (!session || session.state === 'connecting') return;
    if (session.id) {
      try {
        await invoke('console_disconnect', { sessionId: session.id });
      } catch {
        // A remotely closed session may already have left the backend registry.
      }
    }
    terminalRefs.current.delete(key);
    queuedEvents.current.delete(key);
    secretsRef.current.delete(key);
    setSessions((current) => current.filter((candidate) => candidate.key !== key));
    if (snapshot.length === 1) setConnectFormCollapsed(false);
    setActiveKey((currentActive) => {
      if (currentActive !== key) return currentActive;
      const index = snapshot.findIndex((candidate) => candidate.key === key);
      return snapshot[index + 1]?.key ?? snapshot[index - 1]?.key ?? null;
    });
  }, []);

  const sendInput = useCallback(async (key, data) => {
    const session = sessionsRef.current.find((candidate) => candidate.key === key);
    if (!session?.id) return;
    try {
      await invoke('console_send', {
        sessionId: session.id,
        b64: bytesToBase64(encoder.encode(data)),
      });
    } catch (error) {
      updateSession(key, { status: { level: 'down', message: String(error) } });
    }
  }, [updateSession]);

  const resize = useCallback((sessionId, cols, rows) => {
    if (!sessionId) return;
    invoke('console_resize', { sessionId, cols, rows }).catch((error) => {
      const session = sessionsRef.current.find((candidate) => candidate.id === sessionId);
      if (session) updateSession(session.key, { status: { level: 'degraded', message: String(error) } });
    });
  }, [updateSession]);

  const changeTransport = useCallback((nextTransport) => {
    setTransport(nextTransport);
    setFormStatus({ level: 'idle', message: 'Ready for a new connection' });
  }, []);

  const handleFormMessage = useCallback((message) => {
    setFormStatus(message
      ? { level: 'degraded', message }
      : { level: 'idle', message: 'Ready for a new connection' });
  }, []);

  const trustHostKey = async () => {
    const prompt = hostKeyRef.current;
    const pending = pendingConnectRef.current;
    if (!prompt || !pending || prompt.sessionKey !== pending.key) return;
    setTrustingKey(true);
    try {
      await invoke('console_known_hosts_trust', {
        host: prompt.host,
        port: prompt.port,
        fingerprint: prompt.fingerprint,
        keyB64: prompt.keyB64,
      });
      hostKeyRef.current = null;
      setHostKey(null);
      await connect(
        withSecret(pending.params, secretsRef.current.get(pending.key)),
        pending.options,
        pending.key,
      );
    } catch (error) {
      updateSession(pending.key, { status: { level: 'down', message: String(error) } });
    } finally {
      setTrustingKey(false);
    }
  };

  const cancelHostKey = () => {
    const key = hostKeyRef.current?.sessionKey;
    hostKeyRef.current = null;
    pendingConnectRef.current = null;
    setHostKey(null);
    if (key) secretsRef.current.delete(key);
    if (key) updateSession(key, {
      state: 'closed',
      canReconnect: false,
      status: { level: 'idle', message: 'Connection cancelled; host key was not trusted' },
    });
  };

  const activeSession = useMemo(
    () => sessions.find((session) => session.key === activeKey) ?? null,
    [activeKey, sessions],
  );
  const displayedStatus = activeSession?.status ?? formStatus;
  const sessionLimitReached = sessions.filter((session) => (
    session.state === 'connected' || session.state === 'connecting'
  )).length >= 16;

  return (
    <section className="console-page">
      <div className="page-header console-header">
        <div className="page-title-block">
          <span className="page-tag"><span className="page-tag-dot" /> INTERACTIVE ACCESS</span>
          <h1>Console</h1>
        </div>
        <span className="run-state" title={displayedStatus.message}>
          <span className={`status-light ${displayedStatus.level}`} />
          {displayedStatus.message}
        </span>
      </div>

      <ConnectForm
        key={connectFormKey}
        transport={transport}
        onTransportChange={changeTransport}
        connectionState={connecting ? 'connecting' : 'disconnected'}
        onConnect={connect}
        onFormMessage={handleFormMessage}
        hasSessions={sessions.length > 0}
        sessionLimitReached={sessionLimitReached}
        collapsed={connectFormCollapsed}
        onToggleCollapsed={() => setConnectFormCollapsed((current) => !current)}
      />

      {sessions.length > 0 && (
        <SessionTabs
          sessions={sessions}
          activeKey={activeKey}
          onActivate={setActiveKey}
          onRename={(key, name) => updateSession(key, { name })}
          onDisconnect={disconnect}
          onReconnect={reconnect}
          onClose={closeSession}
        />
      )}

      <div className="console-terminal-stack">
        {sessions.length === 0 ? (
          <TerminalPane isActive={isActive} />
        ) : sessions.map((session) => (
          <div
            key={session.key}
            className={session.key === activeKey ? 'console-terminal-session' : 'tab-hidden'}
          >
            <TerminalPane
              ref={(terminal) => setTerminalRef(session.key, terminal)}
              isActive={isActive && session.key === activeKey}
              sessionId={session.id}
              connectionState={session.state}
              sessionName={session.name}
              onInput={(data) => sendInput(session.key, data)}
              onResize={resize}
              localEcho={session.localEcho}
            />
          </div>
        ))}
      </div>
      <HostKeyPrompt hostKey={hostKey} busy={trustingKey} onTrust={trustHostKey} onCancel={cancelHostKey} />
    </section>
  );
}
