import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Channel, invoke } from '@tauri-apps/api/core';
import CloseSessionPrompt from './CloseSessionPrompt';
import ConnectForm from './ConnectForm';
import HostKeyPrompt from './HostKeyPrompt';
import SessionTabs from './SessionTabs';
import TerminalPane from './TerminalPane';
import {
  MAX_CONSOLE_SESSIONS,
  canReconnectAfterError,
  countLiveSessions,
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
  const [pendingClose, setPendingClose] = useState(null);
  const [closingSession, setClosingSession] = useState(false);
  const sessionsRef = useRef([]);
  const activeKeyRef = useRef(null);
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
    activeKeyRef.current = activeKey;
  }, [activeKey]);

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
      // Every close the user did not ask for is recoverable, so the credentials
      // are kept for the reconnect. A deliberate disconnect drops them instead.
      const recoverable = Boolean(event.recoverable);
      if (!recoverable) secretsRef.current.delete(key);
      updateSession(key, {
        id: null,
        state: recoverable ? 'interrupted' : 'closed',
        canReconnect: recoverable,
        status: { level: recoverable ? 'down' : 'idle', message: event.reason },
      });
      writeToTerminal(key, (terminal) => {
        terminal.writeln(recoverable ? `\r\n\x1b[31m${event.reason}\x1b[0m` : `\r\n\x1b[2m${event.reason}\x1b[0m`);
        if (recoverable) {
          terminal.writeln('\x1b[2mPress R to reconnect.\x1b[0m');
          // R only reaches the pane that holds focus, which after an unwatched
          // drop it may not. A background tab is left alone — it takes focus
          // when it is selected.
          if (activeKeyRef.current === key) terminal.focus();
        }
      });
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
        writeToTerminal(key, (terminal) => {
          terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
          if (reconnectable) {
            terminal.writeln('\x1b[2mPress R to reconnect.\x1b[0m');
            if (activeKeyRef.current === key) terminal.focus();
          }
        });
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
      const message = 'Credentials were cleared. Reconnect from the connection form.';
      updateSession(key, { canReconnect: false, status: { level: 'degraded', message } });
      // Said in the terminal too, since that is where the reconnect hint was.
      writeToTerminal(key, (terminal) => terminal.writeln(`\x1b[33m${message}\x1b[0m`));
      return;
    }
    connect(withSecret(session.params, secret), session.options ?? {}, key);
  }, [connect, updateSession, writeToTerminal]);

  const disconnect = useCallback(async (key) => {
    const session = sessionsRef.current.find((candidate) => candidate.key === key);
    if (!session?.id) return;
    // A deliberate disconnect ends the session, so its credentials are no
    // longer needed; a later reconnect goes back through the form. The tab and
    // its scrollback stay, so the transcript is still there to export.
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
      // Closing a live tab is the only way to end a session, so the transport
      // is closed politely here rather than left for the backend to time out.
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

  const activateSession = useCallback((key) => {
    setActiveKey(key);
    // The pane is display:none until this update commits, and a hidden element
    // cannot take focus, so the terminal is focused once it is on screen.
    window.setTimeout(() => terminalRefs.current.get(key)?.focus(), 0);
  }, []);

  const requestClose = useCallback((key) => {
    const session = sessionsRef.current.find((candidate) => candidate.key === key);
    if (!session || session.state === 'connecting') return;
    // Only a live session is worth confirming; a closed tab holds nothing but
    // its scrollback, which Export has already had every chance to capture.
    if (!session.id) {
      closeSession(key);
      return;
    }
    setPendingClose({ key, name: session.name, kind: session.kind });
  }, [closeSession]);

  const confirmClose = useCallback(async () => {
    const key = pendingClose?.key;
    if (!key) return;
    setClosingSession(true);
    try {
      await closeSession(key);
    } finally {
      setClosingSession(false);
      setPendingClose(null);
    }
  }, [closeSession, pendingClose]);

  const exportPendingTranscript = useCallback(() => {
    if (pendingClose) terminalRefs.current.get(pendingClose.key)?.exportTranscript();
  }, [pendingClose]);

  const cancelClose = useCallback(() => setPendingClose(null), []);

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
  const sessionLimitReached = countLiveSessions(sessions) >= MAX_CONSOLE_SESSIONS;

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
          onActivate={activateSession}
          onRename={(key, name) => updateSession(key, { name })}
          onDisconnect={disconnect}
          onReconnect={reconnect}
          onClose={requestClose}
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
              canReconnect={session.canReconnect}
              onReconnectKey={() => reconnect(session.key)}
            />
          </div>
        ))}
      </div>
      <HostKeyPrompt hostKey={hostKey} busy={trustingKey} onTrust={trustHostKey} onCancel={cancelHostKey} />
      <CloseSessionPrompt
        session={pendingClose}
        busy={closingSession}
        onExport={exportPendingTranscript}
        onConfirm={confirmClose}
        onCancel={cancelClose}
      />
    </section>
  );
}
