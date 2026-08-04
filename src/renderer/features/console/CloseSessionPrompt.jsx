import React, { useEffect } from 'react';

export default function CloseSessionPrompt({ session, busy, onExport, onConfirm, onCancel }) {
  useEffect(() => {
    if (!session) return undefined;
    const handleKey = (event) => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [onCancel, session]);

  if (!session) return null;

  return (
    <div className="console-confirm-overlay" role="presentation">
      <section className="console-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="console-close-title">
        <span className="page-tag"><span className="page-tag-dot" /> SESSION STILL LIVE</span>
        <h2 id="console-close-title">Close {session.name}?</h2>
        <p>
          The {session.kind.toUpperCase()} session is still connected. Closing the tab disconnects it
          and discards the terminal output, scrollback included.
        </p>
        <p className="console-confirm-note">
          Export the transcript first if you need a record of this session.
        </p>
        <div className="console-confirm-actions">
          <button type="button" className="secondary" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" className="secondary" onClick={onExport} disabled={busy}>Export transcript</button>
          <button type="button" onClick={onConfirm} disabled={busy}>{busy ? 'Closing…' : 'Disconnect and close'}</button>
        </div>
      </section>
    </div>
  );
}
