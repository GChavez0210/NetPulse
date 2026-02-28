const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('networkAPI', {
  pingHost: (host) => ipcRenderer.invoke('ping:run', host),
  pingSample: (host, options) => ipcRenderer.invoke('ping:sample', host, options),
  startFloodPing: (payload) => ipcRenderer.invoke('ping:floodStart', payload),
  cancelFloodPing: () => ipcRenderer.invoke('ping:floodCancel'),
  onFloodPingSample: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('ping:floodSample', handler);
    return () => ipcRenderer.removeListener('ping:floodSample', handler);
  },
  onFloodPingDone: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('ping:floodDone', handler);
    return () => ipcRenderer.removeListener('ping:floodDone', handler);
  },
  onFloodPingStatus: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('ping:floodStatus', handler);
    return () => ipcRenderer.removeListener('ping:floodStatus', handler);
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
