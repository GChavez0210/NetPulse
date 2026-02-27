/// <reference types="vite/client" />

// Type definitions for the Electron API exposed to the renderer.
interface NetworkApi {
  pingHost: (host: string) => Promise<{ ok: boolean; code: number; output: string }>;
  pingSample: (host: string) => Promise<{ ok: boolean; code: number; latencyMs: number | null; output: string }>;
  runTraceroute: (host: string) => Promise<{ ok: boolean; code: number; output: string }>;
  saveApiKey: (apiKey: string) => Promise<{ ok: boolean }>;
  getApiKey: () => Promise<string>;
}

interface Window {
  networkAPI: NetworkApi;
}
