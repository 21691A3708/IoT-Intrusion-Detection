import { environment } from '../../../environments/environment';

const BASE = environment.apiBaseUrl;
const MC = `${BASE}/api/multiclass`;
const INC = `${MC}/incidents`;
const PR = `${BASE}/api/persistent-responses`;
const RES = `${BASE}/api/responses`;

const id = (value: string) => encodeURIComponent(value);

export const API_ENDPOINTS = {

  health: `${BASE}/api/health`,
  databaseHealth: `${BASE}/api/health/database`,

  model: {
    info: `${MC}/model-info`,
    predict: `${MC}/predict`,
    predictBatch: `${MC}/predict-batch`,
    explain: `${MC}/explain`,
  },

  devices: {
    list: `${BASE}/api/devices`,
    create: `${BASE}/api/devices`,
    profiles: `${MC}/device-profiles`,
  },

  risk: {
    assess: `${MC}/assess-risk`,
  },

  incidents: {
    info: `${INC}/info`,
    list: INC,
    summary: `${INC}/summary`,
    detail: (value: string) => `${INC}/${id(value)}`,
    audit: (value: string) => `${INC}/${id(value)}/audit`,
    status: (value: string) => `${INC}/${id(value)}/status`,
  },

  persistentResponses: {
    info: `${PR}/info`,
    list: PR,
    create: PR,
    detail: (value: string) => `${PR}/${id(value)}`,
    audit: (value: string) => `${PR}/${id(value)}/audit`,
  },

  responsePolicy: {
    info: `${MC}/response-policy`,
    plan: `${MC}/plan-response`,
  },

  simulation: {
    info: `${RES}/info`,
    create: RES,
    detail: (value: string) => `${RES}/${id(value)}`,
    audit: (value: string) => `${RES}/${id(value)}/audit`,
  },

  legacy: {
    predictions: `${BASE}/api/predictions`,
    incidents: `${BASE}/api/incidents`,
    explain: `${BASE}/api/explain`,
    csvUpload: `${BASE}/api/upload/csv`,
    assistant: `${BASE}/api/assistant/chat`,
    websocket: `${environment.websocketBaseUrl}/ws/predictions`,
  },

} as const;
