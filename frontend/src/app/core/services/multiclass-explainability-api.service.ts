import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';

import type {
  TrafficFeatures,
  MulticlassPrediction,
  AttackFamily,
  AttackLabel,
} from '../models/prediction.model';

export interface ShapFeature {
  feature: string;
  feature_value: number;
  shap_value: number;
  impact: string;
}

export interface ShapExplanation {
  base_value: number;
  target_probability: number;
  shap_values_sum: number;
  reconstructed_probability: number;
  additivity_error: number;
  additivity_passed: boolean;
  feature_count: number;
  top_features: ShapFeature[];
  remaining_features_sum: number;
  all_features: ShapFeature[];
}

export interface ExplainabilityRequest {
  features: TrafficFeatures;
  top_n: number;
  target_class: AttackLabel | null;
  source: string;
}

export interface ExplainabilityResponse {
  model_version: string;
  explanation_method: string;
  prediction: MulticlassPrediction;
  explained_label: AttackLabel;
  explained_family: AttackFamily;
  family_explanation: ShapExplanation;
  attack_explanation: ShapExplanation;
  calibrated_attack_probability: number;
  shap_output_shape: number[];
  shap_latency_ms: number;
  total_latency_ms: number;
  explanation_note: string;
}

@Injectable({ providedIn: 'root' })
export class MulticlassExplainabilityApiService {

  private readonly http = inject(HttpClient);

  explain(request: ExplainabilityRequest) {

    return this.http.post<ExplainabilityResponse>(
      `${environment.apiBaseUrl}/api/multiclass/explain`,
      request
    ).pipe(

      timeout(environment.analysisTimeoutMs),

      map(result => {

        if (
          !result ||
          !result.prediction ||
          !result.family_explanation ||
          !result.attack_explanation
        ) {
          throw new Error('Invalid explanation response.');
        }

        this.validateExplanation(
          result.family_explanation,
          request.top_n
        );

        this.validateExplanation(
          result.attack_explanation,
          request.top_n
        );

        if (
          request.target_class !== null &&
          result.explained_label !== request.target_class
        ) {
          throw new Error('Explanation target mismatch.');
        }

        return result;
      })
    );
  }

  private validateExplanation(
    explanation: ShapExplanation,
    topN: number
  ): void {

    const numbers = [
      explanation.base_value,
      explanation.target_probability,
      explanation.shap_values_sum,
      explanation.reconstructed_probability,
      explanation.additivity_error,
      explanation.remaining_features_sum,
    ];

    if (!numbers.every(Number.isFinite)) {
      throw new Error('Invalid SHAP numeric values.');
    }

    if (
      !Array.isArray(explanation.top_features) ||
      !Array.isArray(explanation.all_features) ||
      explanation.all_features.length !== 36 ||
      explanation.feature_count !== 36 ||
      explanation.top_features.length !== topN
    ) {
      throw new Error('Invalid SHAP feature inventory.');
    }

    const names = new Set(
      explanation.all_features.map(row => row.feature)
    );

    if (names.size !== 36) {
      throw new Error('Duplicate SHAP features.');
    }

    for (const row of explanation.all_features) {

      if (
        typeof row.feature !== 'string' ||
        !Number.isFinite(row.feature_value) ||
        !Number.isFinite(row.shap_value)
      ) {
        throw new Error('Invalid SHAP feature contribution.');
      }
    }

    const sum = explanation.all_features.reduce(
      (total, row) => total + row.shap_value,
      0
    );

    const reconstructed = explanation.base_value + sum;

    const tolerance = 1e-6;

    if (
      Math.abs(sum - explanation.shap_values_sum) > tolerance ||
      Math.abs(
        reconstructed - explanation.reconstructed_probability
      ) > tolerance ||
      Math.abs(
        reconstructed - explanation.target_probability
      ) > tolerance ||
      explanation.additivity_passed !== true
    ) {
      throw new Error('SHAP additivity verification failed.');
    }
  }
}
