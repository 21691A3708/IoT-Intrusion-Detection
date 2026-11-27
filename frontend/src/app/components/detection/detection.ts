import { MonitoringApiService } from '../../core/services/monitoring-api.service';

import { inject as comparisonInject, signal as comparisonSignal } from '@angular/core';

import { ContextComparison } from '../../shared/components/context-comparison/context-comparison';

import { ContextComparisonApiService } from '../../core/services/context-comparison-api.service';

import type { ContextComparisonResponse } from '../../core/models/context-comparison.model';

import {
  Component,
  DestroyRef,
  OnInit,
  inject,
  signal,
  computed,
  effect,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { DecimalPipe } from '@angular/common';

import {
  DeviceContextSelector,
} from '../../shared/components/device-context-selector/device-context-selector';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize, TimeoutError } from 'rxjs';
import { RiskAssessmentApiService } from '../../core/services/risk-assessment-api.service';
import { DeviceContextService } from '../../core/services/device-context.service';
import { RiskScore } from '../../shared/components/risk-score/risk-score';
import { RiskContributions } from '../../shared/components/risk-contributions/risk-contributions';
import type { RiskAssessmentResponse } from '../../core/models/risk-assessment.model';

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

} from '../../core/models/prediction.model';

import {
  getApiErrorMessage,
} from '../../shared/utilities/api-error';

@Component({
  selector: 'app-detection',
  standalone: true,
  imports: [ContextComparison,
    FormsModule,
    DecimalPipe,
    DeviceContextSelector,
    RiskScore,
    RiskContributions,
  ],
  templateUrl: './detection.html',
  styleUrl: './detection.scss',
})
export class Detection implements OnInit {

  private readonly sampleApi =
    comparisonInject(MonitoringApiService);

  protected readonly sampleLoading =
    comparisonSignal(false);

  protected loadTestSample(sampleId: string): void {

    if (!sampleId || this.submitting() || this.sampleLoading()) {
      return;
    }

    this.sampleLoading.set(true);
    this.errorMessage.set('');

    const previousInput = this.trafficJson;

    this.sampleApi.getSamples().pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.sampleLoading.set(false))
    ).subscribe({

      next: samples => {

        const sample = samples.find(
          item => item.id === sampleId
        );

        if (!sample) {
          this.errorMessage.set('Test sample not found.');
          return;
        }

        if (
          this.submitting() ||
          previousInput !== this.trafficJson
        ) return;

        this.trafficJson = JSON.stringify(
          sample.features, null, 2
        );

        this.assessmentState.set(null);
        this.comparisonResult.set(null);

        this.notifications.success(
          sample.family + ' sample loaded.',
          'Test sample'
        );
      },

      error: () => {
        this.errorMessage.set('Could not load test sample.');
      },

    });
  }



  private readonly comparisonApi =
    comparisonInject(ContextComparisonApiService);

  protected readonly comparisonResult =
    comparisonSignal<ContextComparisonResponse | null>(null);

  protected compareContexts(): void {

    if (
      this.submitting() ||
      !this.modelInfo() ||
      this.context.loading()
    ) {
      return;
    }

    this.errorMessage.set('');
    this.comparisonResult.set(null);
    this.assessmentState.set(null);

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

    const inputSnapshot = this.trafficJson;

    this.submitting.set(true);

    this.comparisonApi.compare({
      features,
      source: 'manual_context_comparison',
    }).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.submitting.set(false))
    ).subscribe({

      next: response => {

        if (inputSnapshot !== this.trafficJson) {
          return;
        }

        if (
          response.prediction.model_version !==
          this.modelInfo()?.model_version
        ) {
          this.errorMessage.set('Unexpected model version.');
          return;
        }

        this.comparisonResult.set(response);

        this.notifications.success(
          'All device contexts evaluated successfully.',
          'Comparison completed'
        );
      },

      error: error => {
        this.errorMessage.set(
          error instanceof Error
            ? error.message
            : getApiErrorMessage(error)
        );
      },

    });
  }



  private readonly api = inject(MulticlassApiService);
  private readonly riskApi = inject(RiskAssessmentApiService);
  protected readonly context = inject(DeviceContextService);

  private readonly notifications =
    inject(NotificationService);

  private readonly destroyRef = inject(DestroyRef);

  protected readonly modelInfo =
    signal<ModelInfo | null>(null);

  protected readonly modelLoading = signal(false);

  protected readonly modelError = signal('');

  protected readonly submitting = signal(false);

  protected readonly errorMessage = signal('');

  private readonly assessmentState = signal<RiskAssessmentResponse | null>(null);
  private readonly submittedContext = signal<string | null>(null);
  protected readonly assessment = computed(() =>
    this.submittedContext() === this.context.selectedDeviceId()
      ? this.assessmentState() : null
  );
  protected readonly result = computed(() => this.assessment()?.prediction ?? null);

  constructor() {
    effect(() => {
      const selected = this.context.selectedDeviceId();
      if (selected !== this.submittedContext()) {
        this.assessmentState.set(null);
    this.comparisonResult.set(null);
      }
    });
  }

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
    this.assessmentState.set(null);
    this.comparisonResult.set(null);

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

    this.assessmentState.set(null);
    this.comparisonResult.set(null);
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
    this.assessmentState.set(null);
    this.comparisonResult.set(null);

  }

  protected onInputChange(value: string): void {

    this.trafficJson = value;
    this.errorMessage.set('');
    this.assessmentState.set(null);
    this.comparisonResult.set(null);

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

  protected detectTraffic(): void {

    if (this.submitting() || !this.modelInfo() || this.context.loading()) {
      return;
    }

    this.errorMessage.set('');
    this.assessmentState.set(null);
    this.comparisonResult.set(null);

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

    const deviceId = this.context.selectedDeviceId();
    this.submittedContext.set(deviceId);
    this.submitting.set(true);

    this.riskApi.assessRisk({
      features,
      device_id: deviceId,
      source: 'manual',
    }).pipe(

      takeUntilDestroyed(this.destroyRef),

      finalize(() => this.submitting.set(false))

    ).subscribe({

      next: response => {

        if (deviceId !== this.context.selectedDeviceId()) {
          this.errorMessage.set('Device context changed. Analyze again.');
          return;
        }

        if (response.prediction.model_version !== this.modelInfo()?.model_version) {

          this.errorMessage.set(
            'Unexpected prediction response. Check the backend model and API contract.'
          );

          return;

        }

        this.assessmentState.set(response);
        const prediction = response.prediction;

        if (prediction.high_confidence_alert) {

          this.notifications.warning(
            `Predicted family: ${prediction.predicted_family}. Further assessment is recommended.`,
            'High-confidence attack'
          );

        } else {

          this.notifications.success(
            'Multiclass prediction and risk assessment completed.',
            'Analysis completed'
          );

        }

      },

      error: error => {

        const message = error instanceof Error &&
          error.message.startsWith('Invalid risk assessment response:')
          ? error.message : getApiErrorMessage(error);
        this.errorMessage.set(message);
        if (error instanceof TimeoutError || message.startsWith('Invalid risk assessment response:')) {
          this.notifications.error(message, 'Assessment failed');
        }

      },

    });

  }

}
