import { Component, OnInit, inject, DestroyRef } from '@angular/core';

import { CommonModule } from '@angular/common';

import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { Api } from '../../services/api';

import { PredictionWebSocket } from '../../services/prediction-websocket';

interface Incident {
  id: string;
  prediction_id: string;
  device_id: string | null;
  title: string;
  description: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive';
  assigned_to: string | null;
  resolved_at: string | null;
  created_at: string;
}

@Component({
  selector: 'app-incident-management',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './incident-management.html',
  styleUrl: './incident-management.scss',
})
export class IncidentManagement implements OnInit {
  private readonly api = inject(Api);

  private readonly predictionWebSocket = inject(PredictionWebSocket);

  private readonly destroyRef = inject(DestroyRef);

  incidents: Incident[] = [];

  totalIncidents = 0;

  loading = false;

  updatingIncidentId: string | null = null;

  errorMessage = '';

  successMessage = '';

  ngOnInit(): void {
    // Load existing incidents
    this.loadIncidents();

    // Listen for new prediction events
    this.connectPredictionWebSocket();
  }

  // --------------------------------------------------
  // LOAD INCIDENTS
  // --------------------------------------------------

  loadIncidents(): void {
    this.loading = true;

    this.errorMessage = '';

    this.api
      .getIncidents()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response: any) => {
          this.incidents = response.items ?? [];

          this.totalIncidents = response.total ?? 0;

          this.loading = false;
        },

        error: (error) => {
          console.error('Incident loading failed:', error);

          this.errorMessage = 'Unable to load incidents. Please check the backend connection.';

          this.loading = false;
        },
      });
  }

  // --------------------------------------------------
  // REAL-TIME WEBSOCKET CONNECTION
  // --------------------------------------------------

  private connectPredictionWebSocket(): void {
    this.predictionWebSocket
      .connect()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (event) => {
          if (event.event === 'new_prediction') {
            console.log('New prediction received in Incident Management:', event.data);

            // Reload incidents only when a new incident was created
            if (event.data.incident_created) {
              this.successMessage = 'A new security incident has been detected.';

              this.loadIncidents();
            }
          }
        },

        error: (error) => {
          console.error('Incident Management WebSocket error:', error);
        },
      });
  }

  // --------------------------------------------------
  // UPDATE INCIDENT STATUS
  // --------------------------------------------------

  updateStatus(incidentId: string, status: Exclude<Incident['status'], 'open'>): void {
    this.updatingIncidentId = incidentId;

    this.errorMessage = '';

    this.successMessage = '';

    this.api
      .updateIncidentStatus(incidentId, status)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.successMessage = 'Incident status updated successfully.';

          this.updatingIncidentId = null;

          this.loadIncidents();
        },

        error: (error) => {
          console.error('Incident update failed:', error);

          this.errorMessage = error.error?.detail || 'Unable to update incident status.';

          this.updatingIncidentId = null;
        },
      });
  }

  // --------------------------------------------------
  // SEVERITY AND STATUS STYLING
  // --------------------------------------------------

  getSeverityClass(severity: string): string {
    return severity.toLowerCase();
  }

  getStatusClass(status: string): string {
    return status.toLowerCase().replace('_', '-');
  }
}
