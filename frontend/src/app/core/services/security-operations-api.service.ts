import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { timeout } from 'rxjs';

import { environment } from '../../../environments/environment';

import type {
  AttackFamily,
  RiskLevel,
  TrafficFeatures,
  MulticlassPrediction,
} from '../models/prediction.model';

import type {
  RiskAssessment,
} from '../models/risk-assessment.model';

export type IncidentStatus =
  | 'open'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'false_positive';

export interface SecurityIncident {
  incident_id: string;
  title: string;
  description: string;
  severity: RiskLevel;
  status: IncidentStatus;
  predicted_family: AttackFamily;
  prediction_confidence: number;
  calibrated_attack_probability: number;
  risk_score: number;
  recommended_action: string;
  requested_device_identifier: string | null;
  response_id: string | null;
  response_status: string | null;
  source: string;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  allowed_next_statuses?: IncidentStatus[];
  terminal_state?: boolean;
  simulation_only: boolean;
  containment_authorized: boolean;
  real_network_action_executed: boolean;
}

export interface IncidentPage {
  total: number;
  limit: number;
  offset: number;
  returned: number;
  incidents: SecurityIncident[];
}

export interface AuditEvent {
  event_sequence?: number;
  action: string;
  actor_name?: string;
  actor?: string;
  actor_authenticated: boolean;
  previous_status: string | null;
  new_status: string;
  reason?: string;
  details: Record<string, unknown>;
  created_at?: string;
  timestamp?: string;
  simulation_only: boolean;
}

export interface ResponsePlan {
  response_policy_version: string;
  predicted_family: AttackFamily;
  attack_probability: number;
  family_confidence: number;
  risk_score: number;
  risk_level: RiskLevel;
  device_id: string | null;
  device_name: string;
  incident_required: boolean;
  primary_action: string;
  attack_specific_recommendation: string;
  proposed_containment_action: string | null;
  eligible_containment_action: string | null;
  containment_eligible: boolean;
  approval_required: boolean;
  approval_granted: boolean;
  containment_authorized: boolean;
  response_status: string;
  safety_checks: Record<string, unknown>;
  restriction_reasons: string[];
  warnings: string[];
  simulation_only: boolean;
  response_executed: boolean;
  real_network_action_executed: boolean;
}

export interface ResponsePlanningResult {
  prediction: MulticlassPrediction;
  risk_assessment: RiskAssessment;
  response_plan: ResponsePlan;
  mode: string;
  incident_created: boolean;
  response_executed: boolean;
}

export interface PersistentResponse {
  response_id: string;
  status: string;
  prediction: MulticlassPrediction;
  risk_assessment: RiskAssessment;
  response_plan: ResponsePlan;
  incident_id: string | null;
  incident_status: string | null;
  audit_logs: AuditEvent[];
  containment_eligible: boolean;
  approval_granted: boolean;
  containment_authorized: boolean;
  simulation_authorized: boolean;
  simulation_executed: boolean;
  real_network_action_executed: boolean;
  simulation_only: boolean;
  synthetic_fixture: boolean;
  created_at: string;
  updated_at: string;
}

@Injectable({ providedIn: 'root' })
export class SecurityOperationsApiService {

  private readonly http = inject(HttpClient);

  private readonly incidents =
    environment.apiBaseUrl + '/api/multiclass/incidents';

  private readonly responses =
    environment.apiBaseUrl + '/api/persistent-responses';

  listIncidents(
    limit = 20,
    offset = 0,
    filters: Record<string, string> = {}
  ) {

    let params = new HttpParams()
      .set('limit', limit)
      .set('offset', offset);

    for (const [key, value] of Object.entries(filters)) {
      if (value) params = params.set(key, value);
    }

    return this.http.get<IncidentPage>(
      this.incidents,
      { params }
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  getIncident(id: string) {
    return this.http.get<SecurityIncident>(
      `${this.incidents}/${encodeURIComponent(id)}`
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  getIncidentAudit(id: string) {
    return this.http.get<{
      incident_id: string;
      total_events: number;
      audit_logs: AuditEvent[];
    }>(
      `${this.incidents}/${encodeURIComponent(id)}/audit`
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  updateIncidentStatus(
    id: string,
    newStatus: IncidentStatus,
    actor: string,
    reason: string
  ) {
    return this.http.patch<{
      incident: SecurityIncident;
      audit_event: AuditEvent;
      previous_status: IncidentStatus;
      new_status: IncidentStatus;
    }>(
      `${this.incidents}/${encodeURIComponent(id)}/status`,
      {
        new_status: newStatus,
        actor_name: actor,
        reason,
      }
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  getResponse(id: string) {
    return this.http.get<PersistentResponse>(
      `${this.responses}/${encodeURIComponent(id)}`
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  planResponse(
    features: TrafficFeatures,
    deviceId: string | null
  ) {
    return this.http.post<ResponsePlanningResult>(
      environment.apiBaseUrl + '/api/multiclass/plan-response',
      {
        features,
        device_id: deviceId,
        source: 'frontend_response_planning',
      }
    ).pipe(timeout(environment.analysisTimeoutMs));
  }
}
