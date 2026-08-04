import React from 'react';

export default function HostKeyPrompt({ hostKey, busy, onTrust, onCancel }) {
  if (!hostKey) return null;

  return (
    <div className="console-host-key-overlay" role="presentation">
      <section className="console-host-key-dialog" role="dialog" aria-modal="true" aria-labelledby="console-host-key-title">
        <span className="page-tag"><span className="page-tag-dot" /> SSH IDENTITY CHECK</span>
        <h2 id="console-host-key-title">Trust this host for the first time?</h2>
        <p>
          NetPulse has not seen <strong>{hostKey.host}:{hostKey.port}</strong> before.
          Confirm this fingerprint through a trusted channel before continuing.
        </p>
        <dl>
          <div><dt>Algorithm</dt><dd>{hostKey.algorithm}</dd></div>
          <div><dt>SHA-256 fingerprint</dt><dd>{hostKey.fingerprint}</dd></div>
        </dl>
        <p className="console-host-key-note">
          Accepting stores the key in NetPulse’s standard OpenSSH known_hosts file. A later mismatch is always blocked.
        </p>
        <div className="console-host-key-actions">
          <button type="button" className="secondary" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" onClick={onTrust} disabled={busy}>{busy ? 'Saving…' : 'Trust and reconnect'}</button>
        </div>
      </section>
    </div>
  );
}
