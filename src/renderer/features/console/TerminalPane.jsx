import React, {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { SearchAddon } from '@xterm/addon-search';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';

function terminalText(terminal) {
  const buffer = terminal.buffer.active;
  const lines = [];
  for (let index = 0; index < buffer.length; index += 1) {
    lines.push(buffer.getLine(index)?.translateToString(true) ?? '');
  }
  return lines.join('\n').replace(/\s+$/, '');
}

function connectionLabel(connectionState) {
  return {
    connected: 'LIVE',
    connecting: 'CONNECTING',
    interrupted: 'INTERRUPTED',
    disconnected: 'DISCONNECTED',
  }[connectionState] ?? connectionState.toUpperCase();
}

const TerminalPane = forwardRef(function TerminalPane({
  isActive,
  sessionId = null,
  connectionState = 'offline',
  sessionName = 'console',
  onInput,
  onResize,
  localEcho = false,
}, ref) {
  const hostRef = useRef(null);
  const terminalRef = useRef(null);
  const fitAddonRef = useRef(null);
  const searchAddonRef = useRef(null);
  const callbacksRef = useRef({ onInput, onResize, localEcho, sessionId });
  const [search, setSearch] = useState('');
  const [toolbarMessage, setToolbarMessage] = useState('');

  useEffect(() => {
    callbacksRef.current = { onInput, onResize, localEcho, sessionId };
  }, [localEcho, onInput, onResize, sessionId]);

  useImperativeHandle(ref, () => ({
    getSize() {
      const terminal = terminalRef.current;
      return { cols: terminal?.cols || 80, rows: terminal?.rows || 24 };
    },
    write(bytes) {
      terminalRef.current?.write(bytes);
    },
    writeln(message = '') {
      terminalRef.current?.writeln(message);
    },
    reset() {
      terminalRef.current?.reset();
    },
    focus() {
      terminalRef.current?.focus();
    },
  }), []);

  useEffect(() => {
    if (!hostRef.current) return undefined;

    const terminal = new Terminal({
      convertEol: false,
      cursorBlink: true,
      cursorStyle: 'block',
      disableStdin: true,
      fontFamily: 'JetBrains Mono, Consolas, monospace',
      fontSize: 13,
      scrollback: 10_000,
      theme: {
        background: '#080c12',
        foreground: '#d8e2ef',
        cursor: '#55d6be',
        selectionBackground: '#2a4d5a',
      },
    });
    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon();
    terminal.loadAddon(fitAddon);
    terminal.loadAddon(searchAddon);
    terminal.loadAddon(new WebLinksAddon());
    terminal.open(hostRef.current);
    terminal.writeln('\x1b[2mNetPulse Console — configure a transport to begin.\x1b[0m');
    const inputSubscription = terminal.onData((data) => {
      const current = callbacksRef.current;
      if (!current.sessionId) return;
      if (current.localEcho) terminal.write(data);
      current.onInput?.(data);
    });
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;
    searchAddonRef.current = searchAddon;

    return () => {
      inputSubscription.dispose();
      fitAddonRef.current = null;
      searchAddonRef.current = null;
      terminalRef.current = null;
      terminal.dispose();
    };
  }, []);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.options.disableStdin = !sessionId;
  }, [sessionId]);

  useEffect(() => {
    if (!isActive) return undefined;

    let timer;
    const fit = () => {
      const terminal = terminalRef.current;
      const fitAddon = fitAddonRef.current;
      if (!terminal || !fitAddon || !hostRef.current?.clientWidth || !hostRef.current?.clientHeight) return;
      fitAddon.fit();
      if (terminal.cols > 0 && terminal.rows > 0) {
        callbacksRef.current.onResize?.(callbacksRef.current.sessionId, terminal.cols, terminal.rows);
      }
    };
    const scheduleFit = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(fit, 80);
    };

    const frame = window.requestAnimationFrame(fit);
    const observer = new ResizeObserver(scheduleFit);
    observer.observe(hostRef.current);
    window.addEventListener('resize', scheduleFit);
    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(timer);
      observer.disconnect();
      window.removeEventListener('resize', scheduleFit);
    };
    // `sessionId` is a dependency so the size is re-sent once the backend
    // session exists. The fit that runs while connecting has no session to
    // report to, and nothing else would resize the remote PTY afterwards.
  }, [isActive, sessionId]);

  const find = (direction) => {
    if (!search) return;
    const found = direction === 'previous'
      ? searchAddonRef.current?.findPrevious(search)
      : searchAddonRef.current?.findNext(search);
    setToolbarMessage(found ? '' : 'No match');
  };

  const copySelection = async () => {
    const selection = terminalRef.current?.getSelection();
    if (!selection) {
      setToolbarMessage('Select terminal text first');
      return;
    }
    try {
      await navigator.clipboard.writeText(selection);
      setToolbarMessage('Copied');
    } catch {
      setToolbarMessage('Clipboard access was denied');
    }
  };

  const exportText = () => {
    const text = terminalRef.current ? terminalText(terminalRef.current) : '';
    const url = URL.createObjectURL(new Blob([text, '\n'], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    const safeName = sessionName.replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '') || 'console';
    link.download = `netpulse-${safeName}-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    link.click();
    URL.revokeObjectURL(url);
    setToolbarMessage('Exported');
  };

  return (
    <div className="console-terminal-card" aria-label="Interactive terminal">
      <div className="console-terminal-toolbar">
        <div className="console-terminal-identity">
          <span>TERMINAL</span>
          <span>{connectionLabel(connectionState)} · UTF-8 · xterm-256color</span>
        </div>
        <div className="console-terminal-tools">
          <input
            aria-label="Search terminal"
            placeholder="Search output"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') find(event.shiftKey ? 'previous' : 'next');
            }}
          />
          <button type="button" className="secondary" onClick={() => find('previous')} aria-label="Previous match">↑</button>
          <button type="button" className="secondary" onClick={() => find('next')} aria-label="Next match">↓</button>
          <button type="button" className="secondary" onClick={copySelection}>Copy</button>
          <button type="button" className="secondary" onClick={() => terminalRef.current?.clear()}>Clear</button>
          <button type="button" className="secondary" onClick={exportText}>Export</button>
          {toolbarMessage && <span className="console-toolbar-message" role="status">{toolbarMessage}</span>}
        </div>
      </div>
      <div className="console-terminal-host" ref={hostRef} />
    </div>
  );
});

export default TerminalPane;
