import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { forkJoin, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';

import type {
  TrafficFeatures,
  AttackFamily,
  RiskLevel,
} from '../models/prediction.model';

export interface TrafficSample {
  id: string;
  family: AttackFamily;
  features: TrafficFeatures;
}

export interface MonitoringRecord {
  response_id: string;
  prediction_id: string;
  incident_id: string | null;
  requested_device_identifier: string | null;
  predicted_family: AttackFamily;
  predicted_label: number;
  prediction_confidence: number;
  calibrated_attack_probability: number;
  detection_status: string;
  risk_score: number;
  risk_level: RiskLevel;
  source: string;
  status: string;
  incident_created: boolean;
  real_network_action_executed: boolean;
  created_at: string;
}

export interface MonitoringPage {
  total: number;
  limit: number;
  offset: number;
  returned: number;
  records: MonitoringRecord[];
}

export interface IncidentSummary {
  total_incidents: number;
  active_incidents: number;
  active_critical_incidents: number;
  open_incidents: number;
  acknowledged_incidents: number;
  investigating_incidents: number;
  resolved_incidents: number;
  false_positive_incidents: number;
}

export interface ReplayResult {
  response_id: string;
  incident_created: boolean;
  simulation_only: boolean;
  real_network_action_executed: boolean;
}

@Injectable({ providedIn: 'root' })
export class MonitoringApiService {

  private readonly http = inject(HttpClient);

  private readonly base = environment.apiBaseUrl;

  getSamples() {
    return this.http.get<TrafficSample[]>(
      '/test-samples/samples.json'
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  getRecords(limit = 100, offset = 0) {

    const params = new HttpParams()
      .set('limit', limit)
      .set('offset', offset);

    return this.http.get<MonitoringPage>(
      `${this.base}/api/persistent-responses`,
      { params }
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  getIncidentSummary() {
    return this.http.get<IncidentSummary>(
      `${this.base}/api/multiclass/incidents/summary`
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  getDashboard() {
    return forkJoin({
      traffic: this.getRecords(),
      incidents: this.getIncidentSummary(),
    });
  }

  replaySample(
    sample: TrafficSample,
    deviceId: string | null
  ) {
    return this.http.post<ReplayResult>(
      `${this.base}/api/persistent-responses`,
      {
        features: sample.features,
        device_id: deviceId,
        source: 'multiclass_replay',
      }
    ).pipe(timeout(environment.analysisTimeoutMs));
  }
}
