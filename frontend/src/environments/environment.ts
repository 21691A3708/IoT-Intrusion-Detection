export const environment = {
  production: false,
  appName: 'IoT Sentinel',
  apiBaseUrl: 'http://127.0.0.1:8000',
  websocketBaseUrl: 'ws://127.0.0.1:8000',
  requestTimeoutMs: 30000,
  analysisTimeoutMs: 120000,
  defaultPageSize: 20,
  maxPageSize: 100,
  simulationOnly: true,
} as const;
