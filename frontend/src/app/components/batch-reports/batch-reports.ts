import {
  Component,
  OnInit,
  inject,
  signal,
  computed,
  DestroyRef,
} from '@angular/core';

import { CommonModule } from '@angular/common';

import {
  takeUntilDestroyed,
} from '@angular/core/rxjs-interop';

import {
  from,
  concatMap,
  finalize,
} from 'rxjs';

import {
  BatchAnalysisApiService,
} from '../../core/services/batch-analysis-api.service';

import {
  validateTrafficCsv,
} from '../../core/utils/traffic-csv';

import type {
  TrafficFeatures,
  MulticlassPrediction,
  ModelInfo,
} from '../../core/models/prediction.model';

@Component({
  selector: 'app-batch-reports',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './batch-reports.html',
  styleUrl: './batch-reports.scss',
})
export class BatchReports implements OnInit {

  private readonly api = inject(BatchAnalysisApiService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly model = signal<ModelInfo | null>(null);
  protected readonly records = signal<TrafficFeatures[]>([]);
  protected readonly results = signal<MulticlassPrediction[]>([]);

  protected readonly fileName = signal('');
  protected readonly loading = signal(false);
  protected readonly reading = signal(false);
  protected readonly completed = signal(false);
  protected readonly error = signal('');
  protected readonly processed = signal(0);
  protected readonly page = signal(0);

  protected readonly pageSize = 20;

  private readonly families = [
    'Benign', 'DDoS', 'DoS', 'Reconnaissance',
    'BruteForce', 'Spoofing', 'Mirai', 'WebBased',
  ];

  protected readonly progress = computed(() =>
    this.records().length
      ? this.processed() / this.records().length * 100
      : 0
  );

  protected readonly summary = computed(() => {

    const predictions = this.results();

    const total = predictions.length;

    const benign = predictions.filter(
      p => p.predicted_family === 'Benign'
    ).length;

    const alerts = predictions.filter(
      p => p.high_confidence_alert
    ).length;

    const meanProbability = total
      ? predictions.reduce(
          (sum, p) => sum + p.attack_probability, 0
        ) / total
      : 0;

    return {
      total,
      benign,
      attacks: total - benign,
      alerts,
      meanProbability,
    };
  });

  protected readonly distribution = computed(() =>
    this.families.map(family => {

      const count = this.results().filter(
        p => p.predicted_family === family
      ).length;

      return {
        family,
        count,
        percent: this.results().length
          ? count / this.results().length * 100
          : 0,
      };
    })
  );

  protected readonly visibleRows = computed(() =>
    this.results().slice(
      this.page() * this.pageSize,
      (this.page() + 1) * this.pageSize
    )
  );

  ngOnInit(): void {

    this.api.getModelInfo()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: model => this.model.set(model),
        error: () => this.error.set(
          'Unable to load the multiclass model schema.'
        ),
      });
  }

  protected async selectFile(event: Event): Promise<void> {

    if (this.loading() || this.reading()) return;

    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];

    if (!file) return;

    this.records.set([]);
    this.results.set([]);
    this.completed.set(false);
    this.processed.set(0);
    this.page.set(0);
    this.error.set('');
    this.fileName.set(file.name);
    this.reading.set(true);

    try {

      if (!file.name.toLowerCase().endsWith('.csv')) {
        throw new Error('Select a CSV file.');
      }

      if (file.size > 10 * 1024 * 1024) {
        throw new Error('Maximum file size is 10 MB.');
      }

      const model = this.model();

      if (!model) {
        throw new Error('Model schema is unavailable.');
      }

      const text = await file.text();

      this.records.set(
        validateTrafficCsv(text, model.features)
      );

    } catch (error) {

      this.error.set(
        error instanceof Error
          ? error.message
          : 'Unable to read CSV file.'
      );

    } finally {

      this.reading.set(false);
      input.value = '';
    }
  }

  protected analyze(): void {

    if (
      this.loading() ||
      this.reading() ||
      !this.records().length
    ) return;

    this.results.set([]);
    this.processed.set(0);
    this.completed.set(false);
    this.error.set('');
    this.page.set(0);
    this.loading.set(true);

    const records = this.records();
    const chunks: TrafficFeatures[][] = [];

    for (let i = 0; i < records.length; i += 1000) {
      chunks.push(records.slice(i, i + 1000));
    }

    from(chunks).pipe(

      concatMap(chunk => this.api.predictBatch(chunk)),

      takeUntilDestroyed(this.destroyRef),

      finalize(() => this.loading.set(false))

    ).subscribe({

      next: response => {

        if (response.predictions.some(
          p => p.model_version !== this.model()?.model_version
        )) {
          this.error.set('Model version changed during analysis.');
          return;
        }

        this.results.update(
          previous => [...previous, ...response.predictions]
        );

        this.processed.set(this.results().length);
      },

      error: error => {

        this.error.set(
          typeof error?.error?.detail === 'string'
            ? error.error.detail
            : 'Batch analysis failed. Partial results may be shown.'
        );
      },

      complete: () => {

        if (
          this.processed() === records.length &&
          !this.error()
        ) {
          this.completed.set(true);
        }
      },
    });
  }

  protected previousPage(): void {
    this.page.update(value => Math.max(0, value - 1));
  }

  protected nextPage(): void {

    if (
      (this.page() + 1) * this.pageSize <
      this.results().length
    ) {
      this.page.update(value => value + 1);
    }
  }

  protected exportCsv(): void {

    if (!this.completed()) return;

    const lines = [
      [
        'record_number',
        'predicted_family',
        'prediction_confidence',
        'calibrated_attack_probability',
        'detection_status',
        'high_confidence_alert',
        'model_version',
      ].join(',')
    ];

    const escape = (value: unknown) => {

      let text = String(value ?? '');

      if (/^[=+\-@\t\r]/.test(text)) {
        text = "'" + text;
      }

      return '"' + text.replace(/"/g, '""') + '"';
    };

    this.results().forEach((p, index) => {

      lines.push([
        index + 1,
        p.predicted_family,
        p.prediction_confidence,
        p.attack_probability,
        p.detection_status,
        p.high_confidence_alert,
        p.model_version,
      ].map(escape).join(','));
    });

    this.download(
      'iot_sentinel_batch_report.csv',
      lines.join('\r\n'),
      'text/csv;charset=utf-8'
    );
  }

  protected exportJson(): void {

    if (!this.completed()) return;

    const report = {
      report_type: 'multiclass_batch_analysis',
      generated_at: new Date().toISOString(),
      source_file: this.fileName(),
      model_version: this.model()?.model_version,
      total_records: this.records().length,
      summary: this.summary(),
      distribution: this.distribution(),
      predictions: this.results(),
      limitations: [
        'Predictions are not verified ground truth.',
        'BruteForce lacks held-out evaluation support.',
        'Family probabilities are not calibrated.',
        'No contextual risk assessment was performed.',
      ],
      incident_created: false,
      response_executed: false,
    };

    this.download(
      'iot_sentinel_batch_report.json',
      JSON.stringify(report, null, 2),
      'application/json'
    );
  }

  private download(
    filename: string,
    content: string,
    type: string
  ): void {

    const url = URL.createObjectURL(
      new Blob([content], { type })
    );

    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = filename;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
