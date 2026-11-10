import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface HealthResponse {
  status: string;
  service: string;
  timestamp: string;
}

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
  location: string;
  status: 'online' | 'offline' | 'unknown' | 'quarantined';
}

export interface TrafficFeatures {
  Header_Length: number;
  'Protocol Type': number;
  Time_To_Live: number;
  Rate: number;
  fin_flag_number: number;
  syn_flag_number: number;
  rst_flag_number: number;
  psh_flag_number: number;
  ack_flag_number: number;
  ece_flag_number: number;
  cwr_flag_number: number;
  ack_count: number;
  syn_count: number;
  fin_count: number;
  rst_count: number;
  HTTP: number;
  HTTPS: number;
  DNS: number;
  SSH: number;
  IRC: number;
  TCP: number;
  UDP: number;
  DHCP: number;
  ARP: number;
  ICMP: number;
  IGMP: number;
  IPv: number;
  LLC: number;
  'Tot sum': number;
  Min: number;
  Max: number;
  AVG: number;
  Std: number;
  'Tot size': number;
  IAT: number;
  Variance: number;
}

export interface PredictionRequest {
  features: TrafficFeatures;
  device_id: string | null;
  source: 'csv_upload' | 'simulator' | 'device';
}
export interface PredictionHistoryItem {
  id: string;
  device_id: string | null;
  predicted_label: 0 | 1;
  attack_probability: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  source: 'csv_upload' | 'simulator' | 'device';
  model_version: string;
  created_at: string;
}

export interface PredictionHistoryResponse {
  total: number;
  limit: number;
  offset: number;
  items: PredictionHistoryItem[];
}
export interface PredictionResponse {
  id: string;
  device_id: string | null;
  predicted_label: 0 | 1;
  prediction: 'normal' | 'attack';
  attack_probability: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  source: 'csv_upload' | 'simulator' | 'device';
  model_version: string;
  created_at: string;
}

export interface ExplainRequest {
  features: TrafficFeatures;
  top_n: number;
}

export interface SHAPFeature {
  feature: string;
  feature_value: number;
  shap_value: number;
  impact: 'toward_attack' | 'toward_normal' | 'neutral';
}

export interface SHAPExplanation {
  base_value: number;
  shap_values_sum: number;
  top_features: SHAPFeature[];
  explained_class: string;
}

export interface ExplainResponse {
  status: string;
  explanation: SHAPExplanation;
}

export type IncidentStatus =
  'open' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive';

export interface Incident {
  id: string;
  prediction_id: string;
  device_id: string | null;
  title: string;
  description: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: IncidentStatus;
  assigned_to: string | null;
  resolved_at: string | null;
  created_at: string;
}

export interface IncidentResponse {
  total: number;
  limit: number;
  offset: number;
  items: Incident[];
}

export interface CsvUploadResponse {
  message: string;
  filename: string;
  total_records: number;
  normal_records: number;
  attack_records: number;
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  incidents_created: number;
}

export interface DashboardAnalytics {
  totalPredictions: number;
  normalPredictions: number;
  attackPredictions: number;
  activeIncidents: number;
  riskDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

@Injectable({
  providedIn: 'root',
})
export class Api {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = 'http://127.0.0.1:8000';

  getDevices(): Observable<Device[]> {
    return this.http.get<Device[]>(`${this.baseUrl}/api/devices`);
  }

  getHealth(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>(`${this.baseUrl}/api/health`);
  }

  createDevice(device: DeviceCreate): Observable<Device> {
    return this.http.post<Device>(`${this.baseUrl}/api/devices`, device);
  }

  createPrediction(request: PredictionRequest): Observable<PredictionResponse> {
    return this.http.post<PredictionResponse>(`${this.baseUrl}/api/predictions`, request);
  }
  getPredictionHistory(
    limit: number = 50,
    offset: number = 0,
  ): Observable<PredictionHistoryResponse> {
    return this.http.get<PredictionHistoryResponse>(`${this.baseUrl}/api/predictions`, {
      params: {
        limit,
        offset,
      },
    });
  }
  explainTraffic(request: ExplainRequest): Observable<ExplainResponse> {
    return this.http.post<ExplainResponse>(`${this.baseUrl}/api/explain`, request);
  }

  getIncidents(): Observable<IncidentResponse> {
    return this.http.get<IncidentResponse>(`${this.baseUrl}/api/incidents`);
  }

  updateIncidentStatus(
    incidentId: string,
    status: Exclude<IncidentStatus, 'open'>,
  ): Observable<any> {
    return this.http.patch<any>(`${this.baseUrl}/api/incidents/${incidentId}/status`, { status });
  }
  uploadCsv(file: File) {
    const formData = new FormData();
    formData.append('file', file);

    return this.http.post<CsvUploadResponse>(`${this.baseUrl}/api/upload/csv`, formData);
  }

  getDashboardAnalytics(): Observable<DashboardAnalytics> {
    return new Observable((observer) => {
      let predictionsLoaded = false;
      let incidentsLoaded = false;

      let predictionData: PredictionHistoryResponse | null = null;
      let incidentData: IncidentResponse | null = null;

      const calculateAnalytics = () => {
        if (!predictionsLoaded || !incidentsLoaded) {
          return;
        }

        const predictions = predictionData?.items ?? [];
        const incidents = incidentData?.items ?? [];

        const analytics: DashboardAnalytics = {
          totalPredictions: predictions.length,

          normalPredictions: predictions.filter((item) => item.predicted_label === 0).length,

          attackPredictions: predictions.filter((item) => item.predicted_label === 1).length,

          activeIncidents: incidents.filter(
            (incident) => incident.status !== 'resolved' && incident.status !== 'false_positive',
          ).length,

          riskDistribution: {
            low: predictions.filter((item) => item.risk_level === 'low').length,

            medium: predictions.filter((item) => item.risk_level === 'medium').length,

            high: predictions.filter((item) => item.risk_level === 'high').length,

            critical: predictions.filter((item) => item.risk_level === 'critical').length,
          },
        };

        observer.next(analytics);
        observer.complete();
      };

      const predictionsSubscription = this.getPredictionHistory(1000, 0).subscribe({
        next: (response) => {
          predictionData = response;
          predictionsLoaded = true;
          calculateAnalytics();
        },
        error: (error) => observer.error(error),
      });

      const incidentsSubscription = this.getIncidents().subscribe({
        next: (response) => {
          incidentData = response;
          incidentsLoaded = true;
          calculateAnalytics();
        },
        error: (error) => observer.error(error),
      });

      return () => {
        predictionsSubscription.unsubscribe();
        incidentsSubscription.unsubscribe();
      };
    });
  }
}
