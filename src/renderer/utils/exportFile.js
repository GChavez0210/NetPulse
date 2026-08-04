import { invoke } from '@tauri-apps/api/core';

const BROWSER_LOCATION = "this browser's download folder";

/**
 * Writes an export to disk and reports where it went.
 *
 * In the desktop app the backend does the write and returns the absolute path,
 * which is the whole point: a WebView download drops the file somewhere the UI
 * cannot name. A plain browser (vite dev) falls back to the anchor download.
 *
 * @returns {Promise<{ok: boolean, location?: string, error?: string}>}
 */
export async function saveTextFile(fileName, text, mimeType = 'text/plain;charset=utf-8') {
  if (!window.__TAURI_INTERNALS__) {
    const url = URL.createObjectURL(new Blob([text], { type: mimeType }));
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
    return { ok: true, location: BROWSER_LOCATION };
  }

  try {
    const path = await invoke('export_text_file', { fileName, text });
    return { ok: true, location: path };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

/** Formats a save result as a status line, given what was exported. */
export function exportStatusMessage(result, subject) {
  return result.ok
    ? `${subject} saved to ${result.location}`
    : `${subject} could not be saved: ${result.error}`;
}
