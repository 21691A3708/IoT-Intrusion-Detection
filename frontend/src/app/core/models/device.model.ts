export type DeviceStatus =
  | 'online'
  | 'offline'
  | 'unknown'
  | 'quarantined';

export interface Device {
  id: string;
  device_name: string;
  device_identifier: string;
  device_type: string;
  location: string | null;
  status: string;
  last_seen_at: string | null;
  created_at: string;
}

export interface DeviceCreate {
  device_name: string;
  device_identifier: string;
  device_type: string;
  location: string | null;
  status: DeviceStatus;
}

export interface DeviceContextProfile {
  device_id: string;
  device_name: string;
  device_type: string;
  criticality: number;
  exposure: number;
  business_function: string;
  containment_allowed: boolean;
  context_known: boolean;
  context_source: string;
  identity_verified: boolean;
  simulation_only: boolean;
}

export interface DeviceProfilesResponse {
  total_devices: number;
  mode: 'demonstration_only';
  devices: DeviceContextProfile[];
}
