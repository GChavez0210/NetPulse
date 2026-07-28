import React from 'react';

/**
 * Small trash-icon button used in diagnostics/recon card headers to reset a
 * single tool back to its empty state. Disabled when there is nothing to clear.
 */
export default function ClearButton({ onClear, disabled = false, title = 'Clear this tool' }) {
  return (
    <button
      type="button"
      className="diag-clear-btn"
      onClick={onClear}
      disabled={disabled}
      title={title}
      aria-label={title}
    >
      <svg
        width="13"
        height="13"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <polyline points="3 6 5 6 21 6" />
        <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
        <path d="M10 11v6M14 11v6" />
        <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
      </svg>
    </button>
  );
}
