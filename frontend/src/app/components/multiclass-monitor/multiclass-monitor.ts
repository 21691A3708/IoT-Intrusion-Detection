import {
  Component,
  OnInit,
  OnDestroy,
  inject,
  input,
  signal,
  computed,
  DestroyRef,
} from '@angular/core';

import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';

import {
  MonitoringApiService,
  MonitoringRecord,
  TrafficSample,
  IncidentSummary,
} from '../../core/services/monitoring-api.service';

import {
  DeviceContextService,
} from '../../core/services/device-context.service';

import {
  DeviceContextSelector,
} from '../../shared/components/device-context-selector/device-context-selector';

@Component({
  selector: 'app-multiclass-monitor',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    DeviceContextSelector,
  ],
  templateUrl: './multiclass-monitor.html',
  styleUrl: './multiclass-monitor.scss',
})
export class MulticlassMonitor implements OnInit, OnDestroy {

  readonly mode = input<'dashboard' | 'traffic'>('dashboard');

  private readonly api = inject(MonitoringApiService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly context = inject(DeviceContextService);

  protected readonly records = signal<MonitoringRecord[]>([]);
  protected readonly total = signal(0);
  protected readonly incidents = signal<IncidentSummary | null>(null);

  protected readonly loading = signal(false);
  protected readonly error = signal('');
  protected readonly replayError = signal('');

  protected readonly samples = signal<TrafficSample[]>([]);
  protected readonly replayState =
    signal<'stopped' | 'running' | 'paused'>('stopped');

  protected readonly inFlight = signal(false);
  protected readonly processed = signal(0);
  protected readonly replayIncidents = signal(0);
  protected readonly currentFamily = signal('');

  protected intervalSeconds = 3;
  protected selectedFamily = 'all';
  protected recordLimit = 14;

  private replayTimer?: ReturnType<typeof setTimeout>;
  private refreshTimer?: ReturnType<typeof setInterval>;
  private sampleIndex = 0;
  private destroyed = false;

  protected readonly families = [
    'Benign',
    'DDoS',
    'DoS',
    'Reconnaissance',
    'BruteForce',
    'Spoofing',
    'Mirai',
    'WebBased',
  ];

  protected readonly levels = [
    'low', 'medium', 'high', 'critical'
  ];

  protected readonly attackCount = computed(
    () => this.records().filter(
      row => row.predicted_family !== 'Benign'
    ).length
  );

  protected readonly familyDistribution = computed(
    () => this.families.map(family => ({
      family,
      count: this.records().filter(
        row => row.predicted_family === family
      ).length,
    }))
  );

  protected readonly riskDistribution = computed(
    () => this.levels.map(level => ({
      level,
      count: this.records().filter(
        row => row.risk_level === level
      ).length,
    }))
  );

  ngOnInit(): void {

    this.refresh();

    if (this.mode() === 'traffic') {
      this.context.loadProfiles();

      this.api.getSamples()
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: samples => this.samples.set(samples),
          error: () => this.replayError.set(
            'Could not load traffic samples.'
          ),
        });
    }

    this.refreshTimer = setInterval(
      () => this.refresh(), 10000
    );
  }

  protected refresh(): void {

    if (this.loading() || this.destroyed) return;

    this.loading.set(true);
    this.error.set('');

    this.api.getDashboard().pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.loading.set(false))
    ).subscribe({

      next: result => {
        this.records.set(result.traffic.records);
        this.total.set(result.traffic.total);
        this.incidents.set(result.incidents);
      },

      error: () => {
        this.error.set(
          'Monitoring data unavailable. Check backend connection.'
        );
      },

    });
  }

  protected start(): void {

    if (
      this.inFlight() ||
      this.replayState() !== 'stopped' ||
      !this.samples().length
    ) return;

    if (
      !Number.isInteger(this.recordLimit) ||
      this.recordLimit < 1 ||
      this.recordLimit > 100 ||
      !Number.isFinite(this.intervalSeconds) ||
      this.intervalSeconds < 1 ||
      this.intervalSeconds > 60
    ) {
      this.replayError.set('Invalid replay settings.');
      return;
    }

    this.processed.set(0);
    this.replayIncidents.set(0);
    this.sampleIndex = 0;
    this.replayError.set('');
    this.replayState.set('running');

    this.runNext();
  }

  protected pause(): void {
    if (this.replayState() !== 'running') return;
    this.replayState.set('paused');
    clearTimeout(this.replayTimer);
  }

  protected resume(): void {
    if (this.replayState() !== 'paused') return;
    this.replayState.set('running');

    if (!this.inFlight()) {
      this.runNext();
    }
  }

  protected stop(): void {
    this.replayState.set('stopped');
    clearTimeout(this.replayTimer);
  }

  private scheduleNext(): void {

    if (
      this.destroyed ||
      this.replayState() !== 'running'
    ) return;

    if (this.processed() >= this.recordLimit) {
      this.stop();
      return;
    }

    this.replayTimer = setTimeout(
      () => this.runNext(),
      this.intervalSeconds * 1000
    );
  }

  private runNext(): void {

    if (
      this.destroyed ||
      this.inFlight() ||
      this.replayState() !== 'running'
    ) return;

    if (this.processed() >= this.recordLimit) {
      this.stop();
      return;
    }

    const pool = this.samples().filter(
      sample => this.selectedFamily === 'all' ||
        sample.family === this.selectedFamily
    );

    if (!pool.length) {
      this.replayError.set('No matching replay samples.');
      this.stop();
      return;
    }

    const sample = pool[this.sampleIndex % pool.length];

    this.sampleIndex++;
    this.currentFamily.set(sample.family);
    this.inFlight.set(true);

    this.api.replaySample(
      sample,
      this.context.selectedDeviceId()
    ).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.inFlight.set(false))
    ).subscribe({

      next: result => {

        if (
          result.simulation_only !== true ||
          result.real_network_action_executed !== false
        ) {
          this.replayError.set(
            'Unexpected response safety state. Replay stopped.'
          );
          this.stop();
          return;
        }

        this.processed.update(value => value + 1);

        if (result.incident_created) {
          this.replayIncidents.update(value => value + 1);
        }

        this.refresh();

        if (this.processed() >= this.recordLimit) {
          this.stop();
        }
      },

      error: () => {
        this.replayError.set(
          'Replay request failed. Check persisted records before restarting.'
        );
        this.stop();
      },

      complete: () => this.scheduleNext(),

    });
  }

  ngOnDestroy(): void {
    this.destroyed = true;
    this.stop();
    clearInterval(this.refreshTimer);
  }
}
