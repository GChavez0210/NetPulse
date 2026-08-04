import React, { useEffect, useRef, useState } from 'react';
import { MAX_CONSOLE_SESSIONS, countLiveSessions } from './sessionLifecycle.mjs';

// How close to the cap the count has to get before it is worth naming the cap.
const CROWDED_SESSIONS = MAX_CONSOLE_SESSIONS - 4;

export default function SessionTabs({
  sessions,
  activeKey,
  onActivate,
  onRename,
  onDisconnect,
  onReconnect,
  onClose,
}) {
  const [editingKey, setEditingKey] = useState(null);
  const [draftName, setDraftName] = useState('');
  const editRef = useRef(null);
  const liveCount = countLiveSessions(sessions);

  useEffect(() => {
    if (editingKey) {
      editRef.current?.focus();
      editRef.current?.select();
    }
  }, [editingKey]);

  const beginRename = (session) => {
    setEditingKey(session.key);
    setDraftName(session.name);
  };

  const finishRename = (session) => {
    const nextName = draftName.trim();
    if (nextName) onRename(session.key, nextName);
    setEditingKey(null);
  };

  return (
    <div className="console-session-bar">
      <div className="console-session-tabs" role="tablist" aria-label="Console sessions">
        {sessions.map((session) => (
          <div
            className={`console-session-tab ${session.key === activeKey ? 'active' : ''}`}
            key={session.key}
          >
            <span className={`status-light ${session.status.level}`} aria-hidden="true" />
            {editingKey === session.key ? (
              <input
                ref={editRef}
                aria-label={`Rename ${session.name}`}
                value={draftName}
                maxLength={64}
                onChange={(event) => setDraftName(event.target.value)}
                onBlur={() => finishRename(session)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') finishRename(session);
                  if (event.key === 'Escape') setEditingKey(null);
                }}
              />
            ) : (
              <button
                type="button"
                className="console-session-label"
                role="tab"
                aria-selected={session.key === activeKey}
                title={`${session.name} — double-click to rename`}
                onClick={() => onActivate(session.key)}
                onDoubleClick={() => beginRename(session)}
              >
                {session.name}
              </button>
            )}
            <button
              type="button"
              className="console-session-icon"
              aria-label={`Rename ${session.name}`}
              title="Rename tab"
              onClick={() => beginRename(session)}
            >
              ✎
            </button>
            <button
              type="button"
              className="console-session-icon close"
              aria-label={`Close ${session.name}`}
              title={session.state === 'connecting'
                ? 'Wait for the connection attempt to finish'
                : 'Close tab — a live session is disconnected first'}
              disabled={session.state === 'connecting'}
              onClick={() => onClose(session.key)}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      <div className="console-session-actions">
        <span>
          {liveCount >= CROWDED_SESSIONS
            ? `${liveCount} / ${MAX_CONSOLE_SESSIONS} live`
            : `${liveCount} live`}
          {' · '}{sessions.length} {sessions.length === 1 ? 'tab' : 'tabs'}
        </span>
        {sessions.find((session) => session.key === activeKey)?.canReconnect && (
          <button type="button" className="console-reconnect-button" onClick={() => onReconnect(activeKey)}>
            Reconnect active
          </button>
        )}
        {sessions.find((session) => session.key === activeKey)?.state === 'connected' && (
          <button type="button" className="secondary" onClick={() => onDisconnect(activeKey)}>
            Disconnect active
          </button>
        )}
      </div>
    </div>
  );
}
