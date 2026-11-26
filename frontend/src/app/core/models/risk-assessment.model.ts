import type {
  AttackFamily,
  MulticlassPrediction,
  RiskLevel,
  TrafficFeatures,
} from './prediction.model';

export type MaliciousAttackFamily =
  Exclude<AttackFamily, 'Benign'>;


// --------------------------------------------------
// RISK ASSESSMENT REQUEST
// --------------------------------------------------

export interface RiskAssessmentRequest {

  features: TrafficFeatures;

  device_id?: string | null;

  source?: string;

}


// --------------------------------------------------
// DEVICE SECURITY CONTEXT
// --------------------------------------------------

export interface RiskDeviceContext {

  device_id: string | null;

  requested_device_id?: string | null;

  device_name: string;

  device_type: string;

  criticality: number;

  exposure: number;

  business_function: string;

  containment_allowed: boolean;

  context_known: boolean;

  context_source:
    | 'demonstration_inventory'
    | 'unknown_device_fallback';

  identity_verified: false;

  simulation_only: true;

}


// --------------------------------------------------
// ATTACK IMPACT CONTRIBUTION
// --------------------------------------------------

export interface AttackImpactContribution {

  attack_family: MaliciousAttackFamily;

  class_probability: number;

  conditional_probability: number;

  impact_score: number;

  weighted_contribution: number;

}


// --------------------------------------------------
// EXPECTED ATTACK IMPACT
// --------------------------------------------------

export interface AttackImpactAssessment {

  expected_impact: number;

  raw_attack_probability: number;

  impact_contributions: AttackImpactContribution[];

  impact_available: boolean;

  impact_policy_version: string;

  class_probabilities_calibrated?: false;

}


// --------------------------------------------------
// RISK FACTORS
// --------------------------------------------------

export interface RiskFactors {

  criticality: number;

  attack_impact: number;

  exposure: number;

}


// --------------------------------------------------
// RISK WEIGHTS
// --------------------------------------------------

export interface RiskWeights {

  criticality: number;

  attack_impact: number;

  exposure: number;

}


// --------------------------------------------------
// RISK CONTRIBUTIONS
// --------------------------------------------------

export interface RiskContributions {

  criticality: number;

  attack_impact: number;

  exposure: number;

}


// --------------------------------------------------
// RISK RECONSTRUCTION
// --------------------------------------------------

export interface RiskReconstruction {

  contribution_sum: number;

  error: number;

  passed: boolean;

}


// --------------------------------------------------
// RECOMMENDED ACTIONS
// --------------------------------------------------

export type RiskRecommendedAction =
  | 'priority_investigation'
  | 'alert_and_investigate'
  | 'review_suspicious_activity'
  | 'monitor_suspicious_activity'
  | 'monitor_and_verify_device'
  | 'record_and_monitor';


// --------------------------------------------------
// COMPLETE RISK ASSESSMENT
// --------------------------------------------------

export interface RiskAssessment {

  risk_policy_version: string;

  risk_score: number;

  risk_level: RiskLevel;

  attack_probability: number;

  device_context: RiskDeviceContext;

  attack_impact: AttackImpactAssessment;

  risk_factors: RiskFactors;

  risk_weights: RiskWeights;

  risk_contributions: RiskContributions;

  risk_reconstruction: RiskReconstruction;

  recommended_action: RiskRecommendedAction;

  requires_device_verification: boolean;

  containment_authorized: false;

  response_executed: false;

  warnings: string[];

}


// --------------------------------------------------
// COMPLETE API RESPONSE
// --------------------------------------------------

export interface RiskAssessmentResponse {

  prediction: MulticlassPrediction;

  risk_assessment: RiskAssessment;

  mode: 'risk_assessment_only';

  incident_created: false;

  response_executed: false;

  source: string;

}


// --------------------------------------------------
// DISPLAY LABELS
// --------------------------------------------------

export const RISK_LEVEL_LABELS:
  Record<RiskLevel, string> = {

  low: 'Low',

  medium: 'Medium',

  high: 'High',

  critical: 'Critical',

};


export const RISK_ACTION_LABELS:
  Record<RiskRecommendedAction, string> = {

  priority_investigation:
    'Priority investigation',

  alert_and_investigate:
    'Alert and investigate',

  review_suspicious_activity:
    'Review suspicious activity',

  monitor_suspicious_activity:
    'Monitor suspicious activity',

  monitor_and_verify_device:
    'Monitor and verify device',

  record_and_monitor:
    'Record and monitor',

};
