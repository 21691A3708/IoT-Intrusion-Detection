import { Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe, DecimalPipe, UpperCasePipe } from '@angular/common';
import { Api, PredictionHistoryItem } from '../../services/api';

@Component({
  selector: 'app-prediction-history',
  standalone: true,
  imports: [DatePipe, DecimalPipe, UpperCasePipe],
  templateUrl: './prediction-history.html',
  styleUrl: './prediction-history.scss',
})
export class PredictionHistory implements OnInit {
  private readonly api = inject(Api);

  protected readonly predictions = signal<PredictionHistoryItem[]>([]);
  protected readonly total = signal(0);
  protected readonly loading = signal(false);
  protected readonly error = signal('');

  ngOnInit(): void {
    this.loadHistory();
  }

  protected loadHistory(): void {
    this.loading.set(true);
    this.error.set('');

    this.api.getPredictionHistory(50, 0).subscribe({
      next: (response) => {
        this.predictions.set(response.items);
        this.total.set(response.total);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Unable to load prediction history. Please check the backend.');
        this.loading.set(false);
      },
    });
  }

  protected get normalCount(): number {
    return this.predictions().filter((p) => p.predicted_label === 0).length;
  }

  protected get attackCount(): number {
    return this.predictions().filter((p) => p.predicted_label === 1).length;
  }

  protected get highRiskCount(): number {
    return this.predictions().filter((p) => p.risk_level === 'high' || p.risk_level === 'critical')
      .length;
  }
}
