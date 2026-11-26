import { Component, OnInit, inject, signal, DestroyRef } from '@angular/core';

import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { BaseChartDirective } from 'ng2-charts';

import { ChartConfiguration, ChartOptions } from 'chart.js';

import { Api, PredictionHistoryItem } from '../../services/api';

import { PredictionWebSocket } from '../../services/prediction-websocket';

type DateRange = '7days' | '30days' | 'all';

@Component({
  selector: 'app-prediction-trends',
  standalone: true,
  imports: [BaseChartDirective],
  templateUrl: './prediction-trends.html',
  styleUrl: './prediction-trends.scss',
})
export class PredictionTrends implements OnInit {
  private readonly api = inject(Api);

  private readonly predictionWebSocket = inject(PredictionWebSocket);

  private readonly destroyRef = inject(DestroyRef);

  private predictions: PredictionHistoryItem[] = [];

  protected readonly loading = signal(false);

  protected readonly error = signal('');

  protected readonly selectedRange = signal<DateRange>('all');

  // --------------------------------------------------
  // CHART DATA
  // --------------------------------------------------

  protected lineChartData: ChartConfiguration<'line'>['data'] = {
    labels: [],
    datasets: [
      {
        data: [],
        label: 'Normal Predictions',
        borderColor: '#22c55e',
        backgroundColor: 'rgba(34, 197, 94, 0.15)',
        fill: true,
        tension: 0.35,
      },
      {
        data: [],
        label: 'Attack Predictions',
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
        fill: true,
        tension: 0.35,
      },
    ],
  };

  // --------------------------------------------------
  // CHART OPTIONS
  // --------------------------------------------------

  protected readonly lineChartOptions: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,

    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: {
          color: '#e5e7eb',
        },
      },

      tooltip: {
        mode: 'index',
        intersect: false,
      },
    },

    scales: {
      x: {
        ticks: {
          color: '#9ca3af',
        },

        grid: {
          color: 'rgba(148, 163, 184, 0.1)',
        },
      },

      y: {
        beginAtZero: true,

        ticks: {
          precision: 0,
          color: '#9ca3af',
        },

        grid: {
          color: 'rgba(148, 163, 184, 0.1)',
        },

        title: {
          display: true,
          text: 'Number of Predictions',
          color: '#e5e7eb',
        },
      },
    },
  };

  // --------------------------------------------------
  // INITIALIZATION
  // --------------------------------------------------

  ngOnInit(): void {
    // Load initial prediction data
    this.loadPredictionTrends();

    // Connect to real-time prediction events
    this.connectPredictionWebSocket();
  }

  // --------------------------------------------------
  // LOAD PREDICTION TRENDS
  // --------------------------------------------------

  protected loadPredictionTrends(): void {
    this.loading.set(true);

    this.error.set('');

    this.api
      .getPredictionHistory(200, 0)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.predictions = response.items;

          this.updateChart();

          this.loading.set(false);
        },

        error: (err) => {
          console.error('Prediction trends error:', err);

          this.error.set('Unable to load prediction trends. Please try again.');

          this.loading.set(false);
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
            console.log('New prediction received in Prediction Trends:', event.data);

            // Reload the latest 200 predictions
            this.loadPredictionTrends();
          }
        },

        error: (error) => {
          console.error('Prediction Trends WebSocket error:', error);
        },
      });
  }

  // --------------------------------------------------
  // DATE RANGE FILTER
  // --------------------------------------------------

  protected changeRange(range: DateRange): void {
    this.selectedRange.set(range);

    this.updateChart();
  }

  // --------------------------------------------------
  // UPDATE CHART DATA
  // --------------------------------------------------

  private updateChart(): void {
    const now = new Date();

    let filteredPredictions = [...this.predictions];

    if (this.selectedRange() !== 'all') {
      const days = this.selectedRange() === '7days' ? 7 : 30;

      const startDate = new Date(now);

      startDate.setDate(now.getDate() - days + 1);

      startDate.setHours(0, 0, 0, 0);

      filteredPredictions = filteredPredictions.filter((prediction) => {
        const date = new Date(prediction.created_at);

        return !Number.isNaN(date.getTime()) && date >= startDate && date <= now;
      });
    }

    const grouped = new Map<
      string,
      {
        normal: number;
        attack: number;
        date: Date;
      }
    >();

    const sortedPredictions = filteredPredictions.sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    );

    for (const prediction of sortedPredictions) {
      const date = new Date(prediction.created_at);

      if (Number.isNaN(date.getTime())) {
        continue;
      }

      const key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;

      if (!grouped.has(key)) {
        grouped.set(key, {
          normal: 0,
          attack: 0,
          date,
        });
      }

      const counts = grouped.get(key)!;

      if (prediction.predicted_label === 0) {
        counts.normal++;
      } else {
        counts.attack++;
      }
    }

    const entries = Array.from(grouped.values());

    // Update chart labels
    this.lineChartData.labels = entries.map((entry) =>
      entry.date.toLocaleDateString('en-IN', {
        day: '2-digit',
        month: 'short',
      }),
    );

    // Update normal prediction values
    this.lineChartData.datasets[0].data = entries.map((entry) => entry.normal);

    // Update attack prediction values
    this.lineChartData.datasets[1].data = entries.map((entry) => entry.attack);
    this.lineChartData = { ...this.lineChartData, datasets: this.lineChartData.datasets.map(dataset => ({ ...dataset })) };
  }
}
