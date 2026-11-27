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
import { finalize, forkJoin } from 'rxjs';

import {
  SecurityOperationsApiService,
  SecurityIncident,
  IncidentStatus,
  AuditEvent,
  PersistentResponse,
} from '../../core/services/security-operations-api.service';

import {
  MonitoringApiService,
  IncidentSummary,
} from '../../core/services/monitoring-api.service';

import {
  ResponsePolicy,
} from '../../shared/components/response-policy/response-policy';

@Component({
  selector: 'app-incident-management',
  standalone: true,
  imports: [CommonModule, FormsModule, ResponsePolicy],
  templateUrl: './incident-management.html',
  styleUrl: './incident-management.scss',
})
export class IncidentManagement implements OnInit {

  private readonly api = inject(SecurityOperationsApiService);
  private readonly monitoring = inject(MonitoringApiService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly incidents = signal<SecurityIncident[]>([]);
  protected readonly summary = signal<IncidentSummary | null>(null);
  protected readonly selected = signal<SecurityIncident | null>(null);
  protected readonly audit = signal<AuditEvent[]>([]);
  protected readonly response = signal<PersistentResponse | null>(null);

  protected readonly total = signal(0);
  protected readonly offset = signal(0);
  protected readonly loading = signal(false);
  protected readonly detailLoading = signal(false);
  protected readonly updating = signal(false);
  protected readonly responseLoading = signal(false);
  protected readonly error = signal('');
  protected readonly detailError = signal('');
  protected readonly success = signal('');

  protected readonly pageSize = 20;

  protected statusFilter = '';
  protected severityFilter = '';
  protected familyFilter = '';
  protected sourceFilter = '';

  protected actorName = '';
  protected reason = '';
  protected nextStatus: IncidentStatus | '' = '';

  private detailSequence = 0;

  protected readonly families = [
    'Benign', 'DDoS', 'DoS', 'Reconnaissance',
    'BruteForce', 'Spoofing', 'Mirai', 'WebBased',
  ];

  protected readonly statuses: IncidentStatus[] = [
    'open', 'acknowledged', 'investigating',
    'resolved', 'false_positive',
  ];

  ngOnInit(): void {
    this.refresh();
  }

  protected refresh(): void {

    if (this.loading()) return;

    this.loading.set(true);
    this.error.set('');

    forkJoin({
      page: this.api.listIncidents(
        this.pageSize,
        this.offset(),
        {
          status: this.statusFilter,
          severity: this.severityFilter,
          predicted_family: this.familyFilter,
          source: this.sourceFilter.trim(),
        }
      ),
      summary: this.monitoring.getIncidentSummary(),
    }).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.loading.set(false))
    ).subscribe({
      next: result => {
        this.incidents.set(result.page.incidents);
        this.total.set(result.page.total);
        this.summary.set(result.summary);
      },
      error: error => this.error.set(
        this.errorMessage(error)
      ),
    });
  }

  protected applyFilters(): void {
    if (this.loading()) return;
    this.offset.set(0);
    this.refresh();
  }

  protected clearFilters(): void {
    this.statusFilter = '';
    this.severityFilter = '';
    this.familyFilter = '';
    this.sourceFilter = '';
    this.applyFilters();
  }

  protected previousPage(): void {
    if (this.loading()) return;
    this.offset.update(value => Math.max(0, value - this.pageSize));
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

  protected openIncident(id: string): void {

    if (this.updating()) return;

    const sequence = ++this.detailSequence;

    this.selected.set(null);
    this.audit.set([]);
    this.response.set(null);
    this.detailError.set('');
    this.success.set('');
    this.nextStatus = '';
    this.reason = '';
    this.detailLoading.set(true);

    forkJoin({
      incident: this.api.getIncident(id),
      audit: this.api.getIncidentAudit(id),
    }).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => {
        if (sequence === this.detailSequence) {
          this.detailLoading.set(false);
        }
      })
    ).subscribe({
      next: result => {
        if (sequence !== this.detailSequence) return;

        this.selected.set(result.incident);
        this.audit.set(result.audit.audit_logs);
      },
      error: error => {
        if (sequence === this.detailSequence) {
          this.detailError.set(this.errorMessage(error));
        }
      },
    });
  }

  protected closeIncident(): void {
    if (this.updating()) return;
    this.detailSequence++;
    this.selected.set(null);
    this.audit.set([]);
    this.response.set(null);
    this.detailLoading.set(false);
    this.detailError.set('');
    this.success.set('');
  }

  protected updateStatus(): void {

    const incident = this.selected();

    if (!incident || this.updating()) return;

    const actor = this.actorName.trim();
    const reason = this.reason.trim();
    const status = this.nextStatus;

    if (
      !actor || actor.length > 100 ||
      !reason || reason.length > 1000 ||
      !status ||
      !incident.allowed_next_statuses?.includes(status)
    ) {
      this.detailError.set(
        'Enter an analyst name, reason and permitted next status.'
      );
      return;
    }

    if (!window.confirm(
      'Update incident status to ' + this.readable(status) + '?'
    )) return;

    this.updating.set(true);
    this.detailError.set('');
    this.success.set('');

    this.api.updateIncidentStatus(
      incident.incident_id,
      status,
      actor,
      reason
    ).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.updating.set(false))
    ).subscribe({
      next: result => {
        this.selected.set(result.incident);
        this.audit.update(events => [
          ...events, result.audit_event,
        ]);

        this.nextStatus = '';
        this.reason = '';
        this.success.set('Incident status updated and audited.');
        this.refresh();
      },
      error: error => {
        this.detailError.set(
          this.errorMessage(error) +
          ' Refresh the incident before retrying.'
        );
      },
    });
  }

  protected loadResponse(): void {

    const incident = this.selected();

    if (!incident?.response_id || this.responseLoading()) return;

    const sequence = this.detailSequence;

    this.responseLoading.set(true);
    this.detailError.set('');

    this.api.getResponse(incident.response_id).pipe(
      takeUntilDestroyed(this.destroyRef),
      finalize(() => this.responseLoading.set(false))
    ).subscribe({
      next: result => {
        if (sequence === this.detailSequence) {
          this.response.set(result);
        }
      },
      error: error => {
        if (sequence === this.detailSequence) {
          this.detailError.set(this.errorMessage(error));
        }
      },
    });
  }

  protected readable(value: string): string {
    return value.replace(/_/g, ' ');
  }

  private errorMessage(error: any): string {
    return typeof error?.error?.detail === 'string'
      ? error.error.detail
      : error instanceof Error
        ? error.message
        : 'Security operations request failed.';
  }
}
