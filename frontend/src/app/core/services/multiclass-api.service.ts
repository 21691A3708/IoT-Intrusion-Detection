import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';
import { API_ENDPOINTS } from '../config/api-endpoints';

import type {
  ModelInfo,
  MulticlassPredictionRequest,
  MulticlassPredictionResponse,
} from '../models/prediction.model';

@Injectable({
  providedIn: 'root',
})
export class MulticlassApiService {

  private readonly http = inject(HttpClient);

  getModelInfo(): Observable<ModelInfo> {
    return this.http.get<ModelInfo>(
      API_ENDPOINTS.model.info
    ).pipe(
      timeout(environment.requestTimeoutMs)
    );
  }

  predict(
    request: MulticlassPredictionRequest
  ): Observable<MulticlassPredictionResponse> {

    return this.http.post<MulticlassPredictionResponse>(
      API_ENDPOINTS.model.predict,
      request
    ).pipe(
      timeout(environment.analysisTimeoutMs)
    );
  }

}
