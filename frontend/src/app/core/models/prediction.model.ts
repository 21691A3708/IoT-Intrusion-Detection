import type { TrafficFeatures } from '../../services/api';

export type { TrafficFeatures };

export type AttackLabel =
  0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

export type AttackFamily =
  | 'Benign'
  | 'DDoS'
  | 'DoS'
  | 'Reconnaissance'
  | 'BruteForce'
  | 'Spoofing'
  | 'Mirai'
  | 'WebBased';

export const ATTACK_LABELS: Record<AttackLabel, AttackFamily> = {
  0: 'Benign',
  1: 'DDoS',
  2: 'DoS',
  3: 'Reconnaissance',
  4: 'BruteForce',
  5: 'Spoofing',
  6: 'Mirai',
  7: 'WebBased',
};

export type DetectionStatus =
  | 'low_probability'
  | 'suspicious'
  | 'elevated_suspicion'
  | 'high_confidence_attack';

export type RiskLevel =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export interface MulticlassPrediction {
  predicted_label: AttackLabel;
  predicted_family: AttackFamily;
  prediction: 'normal' | 'attack';
  prediction_confidence: number;
  candidate_attack_family: Exclude<AttackFamily, 'Benign'>;
  candidate_attack_probability: number;
  benign_probability: number;
  raw_attack_probability: number;
  attack_probability: number;
  calibrated_attack_probability: number;
  class_probabilities: Record<AttackFamily, number>;
  class_probabilities_calibrated: boolean;
  detection_status: DetectionStatus;
  high_confidence_alert: boolean;
  alert_threshold: number;
  model_version: string;
  calibration_scope: string;
  calibration_independently_validated: boolean;
}

export interface MulticlassPredictionRequest {
  features: TrafficFeatures;
  source?: string;
}

export interface MulticlassPredictionResponse
  extends MulticlassPrediction {
  source: string;
  incident_created: boolean;
  response_executed: boolean;
  mode: 'prediction_only';
}

export interface ModelInfo {
  model_version: string;
  algorithm: string;
  configuration: string;
  feature_count: number;
  features: string[];
  class_count: number;
  labels: Record<string, AttackFamily>;
  calibrated: boolean;
  calibration_scope: string;
  validation_supported_labels: number[];
  high_confidence_threshold: number;
}
