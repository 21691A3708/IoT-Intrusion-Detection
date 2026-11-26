import { Component, OnInit, inject, signal, DestroyRef } from '@angular/core';

import { Title } from '@angular/platform-browser';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { Api, Device, DashboardAnalytics } from '../../services/api';

import { PredictionWebSocket } from '../../services/prediction-websocket';

import { BackendStatus } from '../backend-status/backend-status';
import { Devices } from '../devices/devices';
import { DeviceForm } from '../device-form/device-form';
import { Detection } from '../detection/detection';
import { PredictionHistory } from '../prediction-history/prediction-history';
import { Explainability } from '../explainability/explainability';
import { IncidentManagement } from '../incident-management/incident-management';
import { CsvUpload } from '../csv-upload/csv-upload';
import { PredictionTrends } from '../prediction-trends/prediction-trends';
import { AssistantChat } from '../assistant-chat/assistant-chat';

export type DashboardView = 'dashboard' | 'alerts' | 'devices' | 'traffic' | 'analysis' | 'reports';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    BackendStatus,
    Devices,
    DeviceForm,
    Detection,
    PredictionHistory,
    Explainability,
    IncidentManagement,
    CsvUpload,
    PredictionTrends,
    AssistantChat,
  ],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})
export class Dashboard implements OnInit {
  private readonly api = inject(Api);
  private readonly browserTitle = inject(Title);
  protected readonly menuOpen = signal(false);

  private readonly predictionWebSocket = inject(PredictionWebSocket);

  private readonly destroyRef = inject(DestroyRef);

  // Application title
  protected readonly title = signal('Network Intrusion Detection System');

  // Current sidebar page
  protected readonly activeView = signal<DashboardView>('dashboard');

  // Shared WebSocket connection status
  protected readonly websocketStatus = this.predictionWebSocket.status;

  // Device data
  protected readonly devices = signal<Device[]>([]);
  protected readonly devicesLoading = signal(false);
  protected readonly devicesError = signal('');

  // Dashboard analytics
  protected readonly analytics = signal<DashboardAnalytics | null>(null);
  protected readonly analyticsLoading = signal(false);
  protected readonly analyticsError = signal('');

  // --------------------------------------------------
  // INITIALIZATION
  // --------------------------------------------------

  ngOnInit(): void {
    this.browserTitle.setTitle(`${this.getPageTitle()} | IoT Sentinel`);
    this.loadDevices();
    this.loadAnalytics();
    this.connectPredictionWebSocket();
  }

  // --------------------------------------------------
  // SIDEBAR NAVIGATION
  // --------------------------------------------------

  protected navigateTo(view: DashboardView): void {
    this.activeView.set(view);
    this.menuOpen.set(false);
    this.browserTitle.setTitle(`${this.getPageTitle()} | IoT Sentinel`);
  }

  protected isActive(view: DashboardView): boolean {
    return this.activeView() === view;
  }

  protected getPageTitle(): string {
    const titles: Record<DashboardView, string> = {
      dashboard: 'Security Overview',
      alerts: 'Security Alerts',
      devices: 'IoT Device Management',
      traffic: 'Traffic Monitoring',
      analysis: 'Explainable AI Analysis',
      reports: 'Reports and Batch Analysis',
    };

    return titles[this.activeView()];
  }

  // --------------------------------------------------
  // LOAD REGISTERED DEVICES
  // --------------------------------------------------

  protected loadDevices(showLoading = true): void {
    if (showLoading) {
      this.devicesLoading.set(true);
    }

    this.devicesError.set('');

    this.api
      .getDevices()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.devices.set(response);
          this.devicesLoading.set(false);
        },

        error: (error) => {
          console.error('Device loading failed:', error);

          this.devicesError.set('Could not load devices. Check the backend and retry.');

          this.devicesLoading.set(false);
        },
      });
  }

  // --------------------------------------------------
  // LOAD DASHBOARD ANALYTICS
  // --------------------------------------------------

  protected loadAnalytics(showLoading = true): void {
    if (showLoading) {
      this.analyticsLoading.set(true);
    }

    this.analyticsError.set('');

    this.api
      .getDashboardAnalytics()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.analytics.set(response);
          this.analyticsLoading.set(false);
        },

        error: (error) => {
          console.error('Dashboard analytics loading failed:', error);

          this.analyticsError.set(
            'Could not load dashboard analytics. Check the backend and retry.',
          );

          this.analyticsLoading.set(false);
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
            console.log('Real-time prediction received:', event.data);

            // Refresh analytics when a new prediction arrives.
            this.loadAnalytics(false);
          }
        },

        error: (error) => {
          console.error('Prediction WebSocket error:', error);
        },

        complete: () => {
          console.log('Prediction WebSocket stream completed.');
        },
      });
  }

  // --------------------------------------------------
  // MANUAL REFRESH
  // --------------------------------------------------

  protected refreshDashboard(): void {
    this.loadDevices();
    this.loadAnalytics();
  }
}
