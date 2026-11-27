import {
  Component,
  OnInit,
  inject,
  signal,
  DestroyRef,
} from '@angular/core';

import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';

import {
  SecurityOperationsApiService,
  PersistentResponse,
  ResponsePlanningResult,
} from '../../core/services/security-operations-api.service';

import {
  MonitoringApiService,
  MonitoringRecord,
  TrafficSample,
} from '../../core/services/monitoring-api.service';

import {
  DeviceContextService,
} from '../../core/services/device-context.service';

import {
  DeviceContextSelector,
} from '../../shared/components/device-context-selector/device-context-selector';

import {
  ResponsePolicy,
} from '../../shared/components/response-policy/response-policy';

@Component({
  selector: 'app-response-center',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    DeviceContextSelector,
    ResponsePolicy,
  ],
  templateUrl: './response-center.html',
  styleUrl: './response-center.scss',
})
export class ResponseCenter implements OnInit {

  private readonly api = inject(SecurityOperationsApiService);
  private readonly monitoring = inject(MonitoringApiService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly context = inject(DeviceContextService);

  protected readonly samples = signal<TrafficSample[]>([]);
  protected readonly records = signal<MonitoringRecord[]>([]);

  protected readonly plan = signal<ResponsePlanningResult | null>(null);

  protected readonly selected =
    signal<PersistentResponse | null>(null);

  protected readonly loading = signal(false);
  protected readonly planning = signal(false);
  protected readonly detailLoading = signal(false);
  protected readonly error = signal('');
  protected readonly total = signal(0);
  protected readonly offset = signal(0);

  protected readonly pageSize = 20;

  protected selectedSample = '';

  private detailSequence = 0;

  ngOnInit(): void {

    this.context.loadProfiles();

    this.monitoring.getSamples()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: samples => this.samples.set(samples),
        error: () => this.error.set(
          'Could not load response planning samples.'
        ),
      });

    this.refresh();
  }

  protected refresh(): void {

    if (this.loading()) return;

    this.loading.set(true);
    this.error.set('');

    this.monitoring.getRecords(
      this.pageSize,
      this.offset()
    ).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.loading.set(false))
    ).subscribe({
      next: page => {
        this.records.set(page.records);
        this.total.set(page.total);
      },
      error: error => this.error.set(
        this.errorMessage(error)
      ),
    });
  }

  protected previousPage(): void {
    if (this.loading()) return;

    this.offset.update(
      value => Math.max(0, value - this.pageSize)
    );

    this.refresh();
  }

  protected nextPage(): void {

    if (
      this.loading() ||
      this.offset() + this.pageSize >= this.total()
    ) return;

    this.offset.update(value => value + this.pageSize);
    this.refresh();
  }

  protected generatePlan(): void {

    if (this.planning() || this.context.loading()) return;

    const sample = this.samples().find(
      item => item.id === this.selectedSample
    );

    if (!sample) {
      this.error.set('Select a traffic sample.');
      return;
    }

    this.plan.set(null);
    this.error.set('');
    this.planning.set(true);

    const deviceId = this.context.selectedDeviceId();

    this.api.planResponse(
      sample.features,
      deviceId
    ).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.planning.set(false))
    ).subscribe({
      next: result => {

        if (
          result.mode !== 'response_planning_only' ||
          result.incident_created !== false ||
          result.response_executed !== false ||
          result.response_plan.simulation_only !== true ||
          result.response_plan.containment_authorized !== false ||
          result.response_plan.real_network_action_executed !== false
        ) {
          this.error.set('Unexpected response safety state.');
          return;
        }

        this.plan.set(result);
      },

      error: error => this.error.set(
        this.errorMessage(error)
      ),
    });
  }

  protected inspectResponse(id: string): void {

    const sequence = ++this.detailSequence;

    this.selected.set(null);
    this.detailLoading.set(true);
    this.error.set('');

    this.api.getResponse(id).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => {
        if (sequence === this.detailSequence) {
          this.detailLoading.set(false);
        }
      })
    ).subscribe({
      next: result => {
        if (sequence === this.detailSequence) {
          this.selected.set(result);
        }
      },
      error: error => {
        if (sequence === this.detailSequence) {
          this.error.set(this.errorMessage(error));
        }
      },
    });
  }

  protected closeResponse(): void {
    this.detailSequence++;
    this.selected.set(null);
    this.detailLoading.set(false);
  }

  protected readable(value: string): string {
    return value.replace(/_/g, ' ');
  }

  private errorMessage(error: any): string {
    return typeof error?.error?.detail === 'string'
      ? error.error.detail
      : error instanceof Error
        ? error.message
        : 'Response center request failed.';
  }
}
