import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { timeout, map } from 'rxjs';

import { environment } from '../../../environments/environment';

import type {
  TrafficFeatures,
  MulticlassPrediction,
  ModelInfo,
} from '../models/prediction.model';

export interface BatchPredictionResult {
  total_records: number;
  source: string;
  mode: string;
  predictions: MulticlassPrediction[];
}

@Injectable({ providedIn: 'root' })
export class BatchAnalysisApiService {

  private readonly http = inject(HttpClient);

  private readonly base =
    environment.apiBaseUrl + '/api/multiclass';

  getModelInfo() {
    return this.http.get<ModelInfo>(
      this.base + '/model-info'
    ).pipe(timeout(environment.requestTimeoutMs));
  }

  predictBatch(records: TrafficFeatures[]) {

    if (records.length < 1 || records.length > 1000) {
      throw new Error('Batch size must be between 1 and 1000.');
    }

    return this.http.post<BatchPredictionResult>(
      this.base + '/predict-batch',
      {
        records,
        source: 'frontend_batch_analysis',
      }
    ).pipe(
      timeout(environment.analysisTimeoutMs),
      map(result => {

        if (
          result.total_records !== records.length ||
          !Array.isArray(result.predictions) ||
          result.predictions.length !== records.length
        ) {
          throw new Error('Unexpected batch response.');
        }

        for (const prediction of result.predictions) {

          if (
            !Number.isFinite(prediction.attack_probability) ||
            prediction.attack_probability < 0 ||
            prediction.attack_probability > 1 ||
            !['Benign', 'DDoS', 'DoS', 'Reconnaissance',
              'BruteForce', 'Spoofing', 'Mirai', 'WebBased']
              .includes(prediction.predicted_family)
          ) {
            throw new Error('Invalid prediction returned.');
          }
        }

        return result;
      })
    );
  }
}
