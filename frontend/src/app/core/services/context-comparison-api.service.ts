import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';

import type {
  ContextComparisonRequest,
  ContextComparisonResponse,
} from '../models/context-comparison.model';

import {
  validateRiskAssessmentResponse,
} from './risk-assessment-api.service';

@Injectable({ providedIn: 'root' })
export class ContextComparisonApiService {

  private readonly http = inject(HttpClient);

  compare(
    request: ContextComparisonRequest,
  ): Observable<ContextComparisonResponse> {

    return this.http.post<ContextComparisonResponse>(
      `${environment.apiBaseUrl}/api/multiclass/compare-contexts`,
      request,
    ).pipe(
      timeout(environment.analysisTimeoutMs),

      map(result => {

        if (
          !result ||
          result.mode !== 'context_comparison_only' ||
          result.source !== request.source ||
          result.simulation_only !== true ||
          result.containment_authorized !== false ||
          result.incident_created !== false ||
          result.response_executed !== false ||
          !Array.isArray(result.comparisons) ||
          result.comparisons.length < 2 ||
          result.total_contexts !== result.comparisons.length
        ) {
          throw new Error('Invalid or unsafe comparison response.');
        }

        const ids = new Set(
          result.comparisons.map(row => row.device_id)
        );

        if (
          ids.size !== result.total_contexts ||
          !ids.has(null)
        ) {
          throw new Error('Invalid device context inventory.');
        }

        for (const row of result.comparisons) {

          validateRiskAssessmentResponse(
            {
              prediction: result.prediction,
              risk_assessment: row,
              mode: 'risk_assessment_only',
              source: result.source,
              incident_created: false,
              response_executed: false,
            },
            {
              features: request.features,
              device_id: row.device_id,
              source: request.source,
            },
          );

          if (
            row.device_id !== row.device_context.device_id ||
            row.device_name !== row.device_context.device_name ||
            row.risk_policy_version !== result.risk_policy_version
          ) {
            throw new Error('Comparison context mismatch.');
          }
        }

        const scores = result.comparisons.map(
          row => row.risk_score
        );

        const highest = Math.max(...scores);
        const lowest = Math.min(...scores);

        const near = (a: number, b: number) =>
          Number.isFinite(a) &&
          Number.isFinite(b) &&
          Math.abs(a - b) <= 1e-8;

        if (
          !result.summary ||
          !near(result.summary.highest_risk_score, highest) ||
          !near(result.summary.lowest_risk_score, lowest) ||
          !near(
            result.summary.risk_score_difference,
            highest - lowest
          ) ||
          scores.some(
            (score, index) =>
              index > 0 && score > scores[index - 1]
          )
        ) {
          throw new Error('Invalid comparison summary.');
        }

        const verifyIds = (
          reported: (string | null)[],
          score: number,
        ) => {

          const expected = result.comparisons
            .filter(row => near(row.risk_score, score))
            .map(row => row.device_id);

          return Array.isArray(reported) &&
            reported.length === expected.length &&
            new Set(reported).size === expected.length &&
            expected.every(id => reported.includes(id));
        };

        if (
          !verifyIds(
            result.summary.highest_risk_device_ids,
            highest
          ) ||
          !verifyIds(
            result.summary.lowest_risk_device_ids,
            lowest
          )
        ) {
          throw new Error('Invalid highest or lowest risk devices.');
        }

        return result;
      }),
    );
  }
}
