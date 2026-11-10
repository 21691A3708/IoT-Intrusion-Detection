import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DecimalPipe, UpperCasePipe } from '@angular/common';

import {
  Api,
  TrafficFeatures,
  ExplainRequest,
  ExplainResponse,
  SHAPFeature,
} from '../../services/api';

@Component({
  selector: 'app-explainability',
  standalone: true,
  imports: [FormsModule, DecimalPipe, UpperCasePipe],
  templateUrl: './explainability.html',
  styleUrl: './explainability.scss',
})
export class Explainability {
  private readonly api = inject(Api);

  protected readonly submitting = signal(false);
  protected readonly errorMessage = signal('');
  protected readonly result = signal<ExplainResponse | null>(null);

  protected trafficJson = '';

  protected explainTraffic(): void {
    this.errorMessage.set('');
    this.result.set(null);

    let features: TrafficFeatures;

    try {
      features = JSON.parse(this.trafficJson) as TrafficFeatures;
    } catch {
      this.errorMessage.set('Invalid JSON. Please enter valid traffic features.');
      return;
    }

    if (typeof features !== 'object' || features === null || Array.isArray(features)) {
      this.errorMessage.set('Please enter a valid JSON object.');
      return;
    }

    const request: ExplainRequest = {
      features,
      top_n: 10,
    };

    this.submitting.set(true);

    this.api.explainTraffic(request).subscribe({
      next: (response) => {
        this.result.set(response);
        this.submitting.set(false);
      },
      error: (error) => {
        if (error.status === 400 || error.status === 422) {
          this.errorMessage.set(
            error.error?.detail || 'Invalid traffic features. Check all 36 required features.',
          );
        } else {
          this.errorMessage.set(
            'SHAP explanation failed. Please check whether the backend is running.',
          );
        }

        this.submitting.set(false);
      },
    });
  }

  protected get topFeatures(): SHAPFeature[] {
    return this.result()?.explanation.top_features ?? [];
  }

  protected getBarWidth(value: number): number {
    const maxValue = Math.max(
      ...this.topFeatures.map((feature) => Math.abs(feature.shap_value)),
      0.000001,
    );

    return (Math.abs(value) / maxValue) * 100;
  }
}
