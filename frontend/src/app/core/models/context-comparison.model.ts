import type {
  MulticlassPrediction,
  TrafficFeatures,
} from './prediction.model';

import type {
  RiskAssessment,
} from './risk-assessment.model';

export interface ContextComparisonRequest {
  features: TrafficFeatures;
  source: string;
}

export interface ContextComparisonItem extends RiskAssessment {
  device_id: string | null;
  device_name: string;
}

export interface ContextComparisonSummary {
  highest_risk_score: number;
  lowest_risk_score: number;
  risk_score_difference: number;
  highest_risk_device_ids: (string | null)[];
  lowest_risk_device_ids: (string | null)[];
}

export interface ContextComparisonResponse {
  comparison_version: string;
  risk_policy_version: string;
  mode: 'context_comparison_only';
  prediction: MulticlassPrediction;
  total_contexts: number;
  comparisons: ContextComparisonItem[];
  summary: ContextComparisonSummary;
  source: string;
  simulation_only: true;
  containment_authorized: false;
  incident_created: false;
  response_executed: false;
}
