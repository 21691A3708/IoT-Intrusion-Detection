import {
  Component,
  OnInit,
  inject,
  signal,
  computed,
  DestroyRef,
} from '@angular/core';

import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';

import {
  MulticlassExplainabilityApiService,
  ExplainabilityResponse,
} from '../../core/services/multiclass-explainability-api.service';

import {
  MonitoringApiService,
  TrafficSample,
} from '../../core/services/monitoring-api.service';

import {
  MulticlassApiService,
} from '../../core/services/multiclass-api.service';

import type {
  AttackLabel,
  TrafficFeatures,
  ModelInfo,
} from '../../core/models/prediction.model';

import {
  ShapContributions,
} from '../../shared/components/shap-contributions/shap-contributions';

@Component({
  selector: 'app-explainability',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    ShapContributions,
  ],
  templateUrl: './explainability.html',
  styleUrl: './explainability.scss',
})
export class Explainability implements OnInit {

  private readonly api =
    inject(MulticlassExplainabilityApiService);

  private readonly monitoringApi =
    inject(MonitoringApiService);

  private readonly modelApi =
    inject(MulticlassApiService);

  private readonly destroyRef = inject(DestroyRef);

  protected readonly samples = signal<TrafficSample[]>([]);
  protected readonly model = signal<ModelInfo | null>(null);

  protected readonly result =
    signal<ExplainabilityResponse | null>(null);

  protected readonly loading = signal(false);
  protected readonly error = signal('');
  protected readonly initializationError = signal('');

  protected readonly families = [
    { id: 0, name: 'Benign' },
    { id: 1, name: 'DDoS' },
    { id: 2, name: 'DoS' },
    { id: 3, name: 'Reconnaissance' },
    { id: 4, name: 'BruteForce' },
    { id: 5, name: 'Spoofing' },
    { id: 6, name: 'Mirai' },
    { id: 7, name: 'WebBased' },
  ];

  protected readonly probabilityRows = computed(() => {

    const result = this.result();

    if (!result) return [];

    return Object.entries(
      result.prediction.class_probabilities
    ).map(([family, probability]) => ({
      family,
      probability,
    }));
  });

  protected trafficJson = '';
  protected selectedSample = '';
  protected targetClass = 'auto';
  protected topN = 10;

  ngOnInit(): void {
    this.initialize();
  }

  protected initialize(): void {

    this.initializationError.set('');

    this.modelApi.getModelInfo()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: model => this.model.set(model),
        error: () => this.initializationError.set(
          'Could not load multiclass model information.'
        ),
      });

    this.monitoringApi.getSamples()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: samples => this.samples.set(samples),
        error: () => this.initializationError.set(
          'Could not load test samples. Manual JSON input remains available.'
        ),
      });
  }

  protected loadSample(id: string): void {

    if (this.loading()) return;

    const sample = this.samples().find(
      item => item.id === id
    );

    if (!sample) return;

    this.trafficJson = JSON.stringify(
      sample.features, null, 2
    );

    this.clearResult();
  }

  protected clearResult(): void {
    this.result.set(null);
    this.error.set('');
  }

  protected clear(): void {

    if (this.loading()) return;

    this.trafficJson = '';
    this.selectedSample = '';
    this.clearResult();
  }

  protected loadTemplate(): void {

    const model = this.model();

    if (!model || this.loading()) return;

    this.trafficJson = JSON.stringify(
      Object.fromEntries(
        model.features.map(feature => [feature, 0])
      ),
      null,
      2
    );

    this.selectedSample = '';
    this.clearResult();
  }

  private validateFeatures(): TrafficFeatures {

    const model = this.model();

    if (!model) {
      throw new Error('Model information unavailable.');
    }

    const value: unknown = JSON.parse(this.trafficJson);

    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value)
    ) {
      throw new Error('Input must be a JSON object.');
    }

    const features = value as Record<string, unknown>;

    const missing = model.features.filter(
      name => !Object.prototype.hasOwnProperty.call(
        features, name
      )
    );

    const unexpected = Object.keys(features).filter(
      name => !model.features.includes(name)
    );

    if (missing.length || unexpected.length) {
      throw new Error(
        'Feature schema mismatch. Missing: ' +
        (missing.join(', ') || 'None') +
        '. Unexpected: ' +
        (unexpected.join(', ') || 'None')
      );
    }

    for (const name of model.features) {

      const feature = features[name];

      if (
        typeof feature !== 'number' ||
        !Number.isFinite(feature) ||
        !Number.isFinite(Math.fround(feature))
      ) {
        throw new Error('Invalid numeric feature: ' + name);
      }
    }

    return features as unknown as TrafficFeatures;
  }

  protected explain(): void {

    if (this.loading() || !this.model()) return;

    this.clearResult();

    let features: TrafficFeatures;

    try {
      features = this.validateFeatures();
    } catch (error) {
      this.error.set(
        error instanceof Error
          ? error.message
          : 'Invalid traffic features.'
      );
      return;
    }

    const target = this.targetClass === 'auto'
      ? null
      : Number(this.targetClass) as AttackLabel;

    if (
      target !== null &&
      (!Number.isInteger(target) || target < 0 || target > 7)
    ) {
      this.error.set('Invalid target class.');
      return;
    }

    if (
      !Number.isInteger(this.topN) ||
      this.topN < 1 ||
      this.topN > 36
    ) {
      this.error.set('Invalid explanation depth.');
      return;
    }

    this.loading.set(true);

    this.api.explain({
      features,
      top_n: this.topN,
      target_class: target,
      source: 'frontend_multiclass_explainability',
    }).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.loading.set(false))
    ).subscribe({

      next: response => {

        if (
          response.model_version !==
          this.model()?.model_version
        ) {
          this.error.set('Unexpected explanation model version.');
          return;
        }

        this.result.set(response);
      },

      error: error => {

        const detail = error?.error?.detail;

        this.error.set(
          typeof detail === 'string'
            ? detail
            : error instanceof Error
              ? error.message
              : 'Explanation request failed.'
        );
      },

    });
  }
}
