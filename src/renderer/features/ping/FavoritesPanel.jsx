import React, { useState } from 'react';

export default function FavoritesPanel({ favorites, currentHosts, onLoad, onSave, onDelete, onClose }) {
  const [newGroupName, setNewGroupName] = useState('');

  const handleSave = () => {
    const name = newGroupName.trim();
    if (!name || currentHosts.length === 0) return;
    onSave(name);
    setNewGroupName('');
  };

  return (
    <div className="card favorites-panel">
      <div className="favorites-header">
        <span className="section-label">SAVED HOST GROUPS</span>
        <button className="secondary" style={{ padding: '3px 10px', fontSize: '0.75rem' }} onClick={onClose}>
          Close
        </button>
      </div>

      {favorites.length === 0 ? (
        <p className="empty" style={{ padding: '8px 0', margin: 0 }}>
          No saved groups yet. Add monitors and save them as a group below.
        </p>
      ) : (
        <ul className="favorites-list">
          {favorites.map((group, idx) => (
            <li key={idx} className="favorites-item">
              <div className="favorites-item-info">
                <strong>{group.name}</strong>
                <span className="favorites-item-hosts">{group.hosts.join(', ')}</span>
              </div>
              <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                <button onClick={() => onLoad(group.hosts)}>Load</button>
                <button className="danger" style={{ padding: '4px 8px' }} onClick={() => onDelete(idx)}>
                  ✕
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <div className="favorites-save-row">
        <input
          value={newGroupName}
          onChange={(e) => setNewGroupName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSave()}
          placeholder="Group name..."
          style={{ flex: 1 }}
        />
        <button onClick={handleSave} disabled={!newGroupName.trim() || currentHosts.length === 0}>
          Save Current ({currentHosts.length})
        </button>
      </div>
    </div>
  );
}
