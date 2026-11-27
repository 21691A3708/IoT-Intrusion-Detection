import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import {
  Observable,
  map,
  timeout,
} from 'rxjs';

import { environment } from '../../../environments/environment';

import { API_ENDPOINTS } from '../config/api-endpoints';

import { ATTACK_LABELS } from '../models/prediction.model';

import {
  RISK_ACTION_LABELS,
  type RiskAssessmentRequest,
  type RiskAssessmentResponse,
} from '../models/risk-assessment.model';


const EPSILON = 1e-6;

const RISK_KEYS = [
  'criticality',
  'attack_impact',
  'exposure',
] as const;


// --------------------------------------------------
// VALIDATION HELPERS
// --------------------------------------------------

function requireValid(
  condition: unknown,
  message: string,
): asserts condition {

  if (!condition) {

    throw new Error(
      `Invalid risk assessment response: ${message}`
    );

  }

}


function asObject(
  value: unknown,
  name: string,
): Record<string, unknown> {

  requireValid(
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value),
    `${name} must be an object`,
  );

  return value as Record<string, unknown>;

}


function asNumber(
  value: unknown,
  name: string,
  max = 1,
): number {

  requireValid(
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= max + EPSILON,
    `${name} is outside its valid range`,
  );

  return value;

}


function asText(
  value: unknown,
  name: string,
): string {

  requireValid(
    typeof value === 'string' &&
    value.trim().length > 0,
    `${name} must be a non-empty string`,
  );

  return value;

}


function near(
  actual: number,
  expected: number,
  name: string,
): void {

  requireValid(
    Math.abs(actual - expected) <= EPSILON,
    `${name} is inconsistent`,
  );

}


// --------------------------------------------------
// RISK RESPONSE VALIDATION
// --------------------------------------------------

export function validateRiskAssessmentResponse(
  value: unknown,
  request: RiskAssessmentRequest,
): RiskAssessmentResponse {

  const response = asObject(value, 'response');

  const prediction = asObject(
    response['prediction'],
    'prediction',
  );

  const risk = asObject(
    response['risk_assessment'],
    'risk_assessment',
  );

  const context = asObject(
    risk['device_context'],
    'device_context',
  );

  const impact = asObject(
    risk['attack_impact'],
    'attack_impact',
  );

  const factors = asObject(
    risk['risk_factors'],
    'risk_factors',
  );

  const weights = asObject(
    risk['risk_weights'],
    'risk_weights',
  );

  const contributions = asObject(
    risk['risk_contributions'],
    'risk_contributions',
  );

  const reconstruction = asObject(
    risk['risk_reconstruction'],
    'risk_reconstruction',
  );


  // ------------------------------------------------
  // RESPONSE MODE AND SAFETY
  // ------------------------------------------------

  requireValid(
    response['mode'] === 'risk_assessment_only',
    'unexpected response mode',
  );

  requireValid(
    response['incident_created'] === false &&
    response['response_executed'] === false &&
    risk['response_executed'] === false &&
    risk['containment_authorized'] === false,
    'assessment-only safety contract violated',
  );

  requireValid(
    context['identity_verified'] === false &&
    context['simulation_only'] === true &&
    risk['requires_device_verification'] === true,
    'device safety contract violated',
  );

  requireValid(
    response['source'] === (request.source ?? 'manual'),
    'response source mismatch',
  );


  // ------------------------------------------------
  // PREDICTION VALIDATION
  // ------------------------------------------------

  const families = Object.values(ATTACK_LABELS);

  const label = prediction['predicted_label'];

  requireValid(
    typeof label === 'number' &&
    Number.isInteger(label) &&
    label >= 0 &&
    label <= 7,
    'invalid predicted label',
  );

  const family = prediction['predicted_family'];

  requireValid(
    family === ATTACK_LABELS[
      label as keyof typeof ATTACK_LABELS
    ],
    'predicted family does not match label',
  );

  requireValid(
    prediction['prediction'] ===
      (label === 0 ? 'normal' : 'attack'),
    'prediction type does not match label',
  );

  const probabilities = asObject(
    prediction['class_probabilities'],
    'class_probabilities',
  );

  requireValid(
    Object.keys(probabilities).length === families.length,
    'unexpected class probability count',
  );

  let probabilitySum = 0;
  let rawAttackMass = 0;

  for (const attackFamily of families) {

    const probability = asNumber(
      probabilities[attackFamily],
      attackFamily,
    );

    probabilitySum += probability;

    if (attackFamily !== 'Benign') {
      rawAttackMass += probability;
    }

  }

  near(probabilitySum, 1, 'class probability sum');

  const confidence = asNumber(
    prediction['prediction_confidence'],
    'prediction confidence',
  );

  near(
    confidence,
    asNumber(probabilities[String(family)], 'family probability'),
    'prediction confidence',
  );

  const candidate = prediction['candidate_attack_family'];

  requireValid(
    families.some(f => f !== 'Benign' && f === candidate),
    'invalid candidate attack family',
  );

  near(
    asNumber(
      prediction['candidate_attack_probability'],
      'candidate attack probability',
    ),
    asNumber(probabilities[String(candidate)], 'candidate probability'),
    'candidate attack probability',
  );

  near(
    asNumber(prediction['benign_probability'], 'benign probability'),
    asNumber(probabilities['Benign'], 'Benign'),
    'benign probability',
  );

  near(
    asNumber(prediction['raw_attack_probability'], 'raw attack probability'),
    rawAttackMass,
    'raw attack probability',
  );

  const probability = asNumber(
    prediction['calibrated_attack_probability'],
    'calibrated attack probability',
  );

  near(
    asNumber(prediction['attack_probability'], 'attack probability'),
    probability,
    'prediction attack probability',
  );

  near(
    asNumber(risk['attack_probability'], 'risk attack probability'),
    probability,
    'risk attack probability',
  );

  requireValid(
    prediction['class_probabilities_calibrated'] === false &&
    prediction['calibration_independently_validated'] === false &&
    prediction['calibration_scope'] === 'binary_attack_probability',
    'unexpected calibration metadata',
  );

  asText(prediction['model_version'], 'model version');

  const expectedDetectionStatus =
    probability >= 0.90 ? 'high_confidence_attack' :
    probability >= 0.75 ? 'elevated_suspicion' :
    probability >= 0.50 ? 'suspicious' :
    'low_probability';

  requireValid(
    prediction['detection_status'] === expectedDetectionStatus &&
    prediction['high_confidence_alert'] === (probability >= 0.90),
    'inconsistent detection status',
  );

  near(
    asNumber(prediction['alert_threshold'], 'alert threshold'),
    0.90,
    'alert threshold',
  );


  // ------------------------------------------------
  // DEVICE CONTEXT VALIDATION
  // ------------------------------------------------

  const criticality = asNumber(
    context['criticality'],
    'device criticality',
  );

  const exposure = asNumber(
    context['exposure'],
    'device exposure',
  );

  asText(context['device_name'], 'device name');
  asText(context['device_type'], 'device type');
  asText(context['business_function'], 'business function');

  requireValid(
    typeof context['context_known'] === 'boolean' &&
    typeof context['containment_allowed'] === 'boolean',
    'invalid device context flags',
  );

  if (context['context_known'] === true) {

    requireValid(
      typeof context['device_id'] === 'string' &&
      context['device_id'] === request.device_id &&
      context['context_source'] === 'demonstration_inventory',
      'selected device context mismatch',
    );

  } else {

    requireValid(
      context['device_id'] === null &&
      context['requested_device_id'] === (request.device_id ?? null) &&
      context['context_source'] === 'unknown_device_fallback' &&
      context['containment_allowed'] === false,
      'invalid unknown-device fallback',
    );

    near(criticality, 0.50, 'fallback criticality');
    near(exposure, 0.50, 'fallback exposure');

  }


  // ------------------------------------------------
  // EXPECTED ATTACK IMPACT
  // ------------------------------------------------

  const expectedImpact = asNumber(
    impact['expected_impact'],
    'expected attack impact',
  );

  requireValid(
    impact['impact_policy_version'] === 'attack_impact_v1',
    'unsupported attack impact policy',
  );

  near(
    asNumber(impact['raw_attack_probability'], 'impact attack mass'),
    rawAttackMass,
    'impact attack mass',
  );

  const impactRows = impact['impact_contributions'];

  requireValid(
    Array.isArray(impactRows),
    'impact contributions must be an array',
  );

  if (rawAttackMass <= 1e-12) {

    requireValid(
      impact['impact_available'] === false &&
      impactRows.length === 0,
      'invalid unavailable-impact response',
    );

    near(expectedImpact, 0, 'unavailable attack impact');

  } else {

    requireValid(
      impact['impact_available'] === true &&
      impact['class_probabilities_calibrated'] === false &&
      impactRows.length === 7,
      'invalid attack impact metadata',
    );

    const seen = new Set<string>();

    let impactSum = 0;
    let conditionalSum = 0;

    for (const item of impactRows) {

      const row = asObject(item, 'impact contribution');

      const attackFamily = asText(
        row['attack_family'],
        'impact attack family',
      );

      requireValid(
        families.some(f => f !== 'Benign' && f === attackFamily) &&
        !seen.has(attackFamily),
        'invalid or duplicate impact family',
      );

      seen.add(attackFamily);

      const classProbability = asNumber(
        row['class_probability'],
        'impact class probability',
      );

      const conditional = asNumber(
        row['conditional_probability'],
        'conditional probability',
      );

      const impactScore = asNumber(
        row['impact_score'],
        'family impact score',
      );

      const weighted = asNumber(
        row['weighted_contribution'],
        'weighted impact contribution',
      );

      near(
        classProbability,
        asNumber(probabilities[attackFamily], attackFamily),
        'impact class probability',
      );

      near(
        conditional,
        classProbability / rawAttackMass,
        'conditional attack probability',
      );

      near(
        weighted,
        conditional * impactScore,
        'weighted attack impact',
      );

      conditionalSum += conditional;
      impactSum += weighted;

    }

    near(conditionalSum, 1, 'conditional probability sum');
    near(impactSum, expectedImpact, 'expected attack impact');

  }


  // ------------------------------------------------
  // RISK CALCULATION VALIDATION
  // ------------------------------------------------

  requireValid(
    risk['risk_policy_version'] === 'context_risk_v1',
    'unsupported risk policy',
  );

  const score = asNumber(
    risk['risk_score'],
    'risk score',
    100,
  );

  const expectedLevel =
    score >= 75 ? 'critical' :
    score >= 50 ? 'high' :
    score >= 25 ? 'medium' :
    'low';

  requireValid(
    risk['risk_level'] === expectedLevel,
    'risk level does not match score',
  );

  const expectedFactors = {
    criticality,
    attack_impact: expectedImpact,
    exposure,
  };

  const expectedWeights = {
    criticality: 0.40,
    attack_impact: 0.40,
    exposure: 0.20,
  };

  let reconstructedScore = 0;

  for (const key of RISK_KEYS) {

    const factor = asNumber(
      factors[key],
      `${key} factor`,
    );

    const weight = asNumber(
      weights[key],
      `${key} weight`,
    );

    const contribution = asNumber(
      contributions[key],
      `${key} contribution`,
      100,
    );

    near(factor, expectedFactors[key], `${key} factor`);

    near(weight, expectedWeights[key], `${key} weight`);

    near(
      contribution,
      100 * probability * weight * factor,
      `${key} contribution`,
    );

    reconstructedScore += contribution;

  }

  near(reconstructedScore, score, 'risk score reconstruction');

  near(
    asNumber(reconstruction['contribution_sum'], 'contribution sum', 100),
    reconstructedScore,
    'reported contribution sum',
  );

  const reconstructionError = asNumber(
    reconstruction['error'],
    'reconstruction error',
    100,
  );

  requireValid(
    reconstruction['passed'] === true &&
    reconstructionError <= 1e-8,
    'backend risk reconstruction failed',
  );


  // ------------------------------------------------
  // RECOMMENDATIONS AND WARNINGS
  // ------------------------------------------------

  const action = asText(
    risk['recommended_action'],
    'recommended action',
  );

  requireValid(
    Object.prototype.hasOwnProperty.call(
      RISK_ACTION_LABELS,
      action,
    ),
    'unsupported recommended action',
  );

  const warnings = risk['warnings'];

  requireValid(
    Array.isArray(warnings) &&
    warnings.every(
      warning =>
        typeof warning === 'string' &&
        warning.trim().length > 0,
    ),
    'invalid risk warnings',
  );

  return value as RiskAssessmentResponse;

}


// --------------------------------------------------
// ANGULAR HTTP SERVICE
// --------------------------------------------------

@Injectable({
  providedIn: 'root',
})
export class RiskAssessmentApiService {

  private readonly http = inject(HttpClient);


  assessRisk(
    request: RiskAssessmentRequest,
  ): Observable<RiskAssessmentResponse> {

    return this.http.post<unknown>(

      API_ENDPOINTS.risk.assess,

      request,

    ).pipe(

      timeout(environment.analysisTimeoutMs),

      map(response =>
        validateRiskAssessmentResponse(response, request)
      ),

    );

  }

}
