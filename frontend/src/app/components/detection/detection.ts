import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { UpperCasePipe } from '@angular/common';
import { Api, TrafficFeatures, PredictionRequest, PredictionResponse } from '../../services/api';

@Component({
  selector: 'app-detection',
  standalone: true,
  imports: [FormsModule, UpperCasePipe],
  templateUrl: './detection.html',
  styleUrl: './detection.scss',
})
export class Detection {
  private readonly api = inject(Api);

  protected readonly submitting = signal(false);
  protected readonly errorMessage = signal('');
  protected readonly result = signal<PredictionResponse | null>(null);

  protected trafficJson = '';

  protected detectTraffic(): void {
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
      this.errorMessage.set('Traffic features must be a JSON object.');
      return;
    }

    const request: PredictionRequest = {
      features,
      device_id: null,
      source: 'simulator',
    };

    this.submitting.set(true);

    this.api.createPrediction(request).subscribe({
      next: (response) => {
        this.result.set(response);
        this.submitting.set(false);
      },
      error: (error) => {
        if (error.status === 422) {
          this.errorMessage.set(
            'Invalid or incomplete traffic features. Please check all 36 required feature names and values.',
          );
        } else {
          this.errorMessage.set(
            'Prediction failed. Please check whether the FastAPI backend is running.',
          );
        }

        this.submitting.set(false);
      },
    });
  }
}
