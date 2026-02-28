import { useState } from 'react';

export default function ThemeExample({ theme = 'dark', onToggleTheme }) {
  const [inputValue, setInputValue] = useState('example.net');

  return (
    <section className="glass demo-theme-block">
      <h3>Theme System Preview</h3>
      <div className="demo-theme-grid">
        <article className="card demo-card">
          <h4>Network Health</h4>
          <p>Premium neomorphic + glass UI baseline.</p>
          <span className="status-success">Stable</span>
        </article>

        <article className="card demo-card">
          <label htmlFor="demo-target">Target</label>
          <input
            id="demo-target"
            className="input-well"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="Enter hostname"
          />
          <div className="demo-row">
            <button className="btn btn-primary">Run Check</button>
            <button className="btn btn-active">Pressed</button>
          </div>
          <div className="demo-row">
            <span className="status-warning">Warning</span>
            <span className="status-danger">Critical</span>
          </div>
        </article>
      </div>

      <button className="btn btn-primary" onClick={onToggleTheme}>
        Toggle Theme ({theme === 'dark' ? 'Light' : 'Dark'})
      </button>
    </section>
  );
}
