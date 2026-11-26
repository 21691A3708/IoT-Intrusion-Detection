import {
  Component,
  DestroyRef,
  OnInit,
  inject,
  signal,
  computed,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { DecimalPipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';

import {
  MulticlassApiService,
} from '../../core/services/multiclass-api.service';

import {
  NotificationService,
} from '../../core/services/notification.service';

import {
  ATTACK_LABELS,
} from '../../core/models/prediction.model';

import type {
  ModelInfo,
  TrafficFeatures,
  AttackFamily,
  MulticlassPredictionResponse,
} from '../../core/models/prediction.model';

import {
  getApiErrorMessage,
} from '../../shared/utilities/api-error';

@Component({
  selector: 'app-detection',
  standalone: true,
  imports: [FormsModule, DecimalPipe],
  templateUrl: './detection.html',
  styleUrl: './detection.scss',
})
export class Detection implements OnInit {

  private readonly api = inject(MulticlassApiService);

  private readonly notifications =
    inject(NotificationService);

  private readonly destroyRef = inject(DestroyRef);

  protected readonly modelInfo =
    signal<ModelInfo | null>(null);

  protected readonly modelLoading = signal(false);

  protected readonly modelError = signal('');

  protected readonly submitting = signal(false);

  protected readonly errorMessage = signal('');

  protected readonly result =
    signal<MulticlassPredictionResponse | null>(null);

  protected readonly families =
    Object.values(ATTACK_LABELS);

  protected trafficJson = '';

  protected readonly statusLabels: Record<string, string> = {
    low_probability: 'Low attack probability',
    suspicious: 'Suspicious traffic',
    elevated_suspicion: 'Elevated suspicion',
    high_confidence_attack: 'High-confidence attack',
  };

  protected readonly probabilityRows = computed(() => {

    const prediction = this.result();

    if (!prediction) {
      return [];
    }

    return this.families.map(family => ({
      family,
      probability: prediction.class_probabilities[family],
      predicted: prediction.predicted_family === family,
    }));

  });

  protected readonly unsupportedClass = computed(() => {

    const prediction = this.result();
    const model = this.modelInfo();

    if (!prediction || !model) {
      return false;
    }

    return !model.validation_supported_labels.includes(
      prediction.predicted_label
    );

  });

  ngOnInit(): void {
    this.loadModelInfo();
  }

  protected loadModelInfo(): void {

    if (this.modelLoading() || this.submitting()) {
      return;
    }

    this.modelLoading.set(true);
    this.modelError.set('');
    this.modelInfo.set(null);

    this.api.getModelInfo().pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.modelLoading.set(false))
    ).subscribe({

      next: info => {

        if (
          !Array.isArray(info.features) ||
          info.feature_count !== 36 ||
          info.features.length !== 36 ||
          info.class_count !== 8
        ) {
          this.modelError.set(
            'Unexpected model configuration.'
          );
          return;
        }

        this.modelInfo.set(info);

      },

      error: error => {
        this.modelError.set(getApiErrorMessage(error));
      },

    });

  }

  protected loadTemplate(): void {

    const model = this.modelInfo();

    if (!model || this.submitting()) {
      return;
    }

    const template = Object.fromEntries(
      model.features.map(feature => [feature, null])
    );

    this.trafficJson = JSON.stringify(
      template, null, 2
    );

    this.result.set(null);
    this.errorMessage.set('');

    this.notifications.info(
      'Replace every null value with a measured numerical feature.',
      'Feature template loaded'
    );

  }

  protected clearInput(): void {

    if (this.submitting()) {
      return;
    }

    this.trafficJson = '';
    this.errorMessage.set('');
    this.result.set(null);

  }

  protected onInputChange(value: string): void {

    this.trafficJson = value;
    this.errorMessage.set('');
    this.result.set(null);

  }

  private validateFeatures(): TrafficFeatures {

    const model = this.modelInfo();

    if (!model) {
      throw new Error(
        'Model information is unavailable.'
      );
    }

    let parsed: unknown;

    try {
      parsed = JSON.parse(this.trafficJson);
    } catch {
      throw new Error(
        'Invalid JSON. Enter a valid traffic feature object.'
      );
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new Error(
        'Traffic features must be a JSON object.'
      );
    }

    const input = parsed as Record<string, unknown>;

    const missing = model.features.filter(
      feature => !Object.prototype.hasOwnProperty.call(
        input, feature
      )
    );

    if (missing.length > 0) {
      throw new Error(
        `Missing features: ${missing.join(', ')}`
      );
    }

    const extra = Object.keys(input).filter(
      feature => !model.features.includes(feature)
    );

    if (extra.length > 0) {
      throw new Error(
        `Unexpected features: ${extra.join(', ')}`
      );
    }

    const invalid = model.features.filter(feature => {

      const value = input[feature];

      return (
        typeof value !== 'number' ||
        !Number.isFinite(value) ||
        Math.abs(value) > 3.4028234663852886e38
      );

    });

    if (invalid.length > 0) {
      throw new Error(
        `Invalid numerical values: ${invalid.join(', ')}`
      );
    }

    const ordered = Object.fromEntries(
      model.features.map(feature => [
        feature,
        input[feature],
      ])
    );

    return ordered as unknown as TrafficFeatures;

  }

  private validateResponse(
    response: MulticlassPredictionResponse
  ): boolean {

    const model = this.modelInfo();

    const validProbability = (value: unknown): boolean =>
      typeof value === 'number' &&
      Number.isFinite(value) &&
      value >= 0 &&
      value <= 1;

    if (
      !response ||
      !model ||
      response.model_version !== model.model_version ||
      ATTACK_LABELS[response.predicted_label] !==
        response.predicted_family ||
      !validProbability(response.prediction_confidence) ||
      !validProbability(response.raw_attack_probability) ||
      !validProbability(response.calibrated_attack_probability) ||
      !response.class_probabilities ||
      !this.families.every(family =>
        validProbability(
          response.class_probabilities[family]
        )
      ) ||
      !Object.prototype.hasOwnProperty.call(
        this.statusLabels,
        response.detection_status
      ) ||
      response.mode !== 'prediction_only' ||
      response.incident_created !== false ||
      response.response_executed !== false
    ) {
      return false;
    }

    const sum = this.families.reduce(
      (total, family) =>
        total + response.class_probabilities[family],
      0
    );

    return Math.abs(sum - 1) < 0.0001;

  }

  protected detectTraffic(): void {

    if (this.submitting() || !this.modelInfo()) {
      return;
    }

    this.errorMessage.set('');
    this.result.set(null);

    let features: TrafficFeatures;

    try {
      features = this.validateFeatures();
    } catch (error) {

      this.errorMessage.set(
        error instanceof Error
          ? error.message
          : 'Invalid traffic features.'
      );

      return;

    }

    this.submitting.set(true);

    this.api.predict({
      features,
      source: 'manual',
    }).pipe(

      takeUntilDestroyed(this.destroyRef),

      finalize(() => this.submitting.set(false))

    ).subscribe({

      next: response => {

        if (!this.validateResponse(response)) {

          this.errorMessage.set(
            'Unexpected prediction response. Check the backend model and API contract.'
          );

          return;

        }

        this.result.set(response);

        if (response.high_confidence_alert) {

          this.notifications.warning(
            `Predicted family: ${response.predicted_family}. Further assessment is recommended.`,
            'High-confidence attack'
          );

        } else {

          this.notifications.success(
            'Multiclass prediction completed.',
            'Analysis completed'
          );

        }

      },

      error: error => {

        this.errorMessage.set(
          getApiErrorMessage(error)
        );

      },

    });

  }

}
