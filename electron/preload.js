const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('networkAPI', {
  pingHost: (host) => ipcRenderer.invoke('ping:run', host),
  pingSample: (host, options) => ipcRenderer.invoke('ping:sample', host, options),
  runRapidPing: (host, count, jobId) => ipcRenderer.invoke('ping:rapid', host, count, jobId),
  onRapidPingUpdate: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('ping:rapid:update', handler);
    return () => ipcRenderer.removeListener('ping:rapid:update', handler);
  },
  runTraceroute: (host) => ipcRenderer.invoke('trace:run', host),
  runTcpPing: (host, port, timeoutMs) => ipcRenderer.invoke('tcp:ping', host, port, timeoutMs),
  runMtr: (host, rounds) => ipcRenderer.invoke('mtr:run', host, rounds),
  queryDns: (domain, recordType) => ipcRenderer.invoke('dns:query', domain, recordType),
  runPortScan: (host, ports, timeoutMs) => ipcRenderer.invoke('portscan:run', host, ports, timeoutMs),
  lookupWhois: (domain, apiKey) => ipcRenderer.invoke('whois:lookup', domain, apiKey),
  saveApiKey: (apiKey) => ipcRenderer.invoke('settings:setApiKey', apiKey),
  getApiKey: () => ipcRenderer.invoke('settings:getApiKey')
});
