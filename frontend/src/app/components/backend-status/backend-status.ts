import { Component, OnInit, inject, signal } from '@angular/core';
import { Api, HealthResponse } from '../../services/api';

@Component({
  selector: 'app-backend-status',
  standalone: true,
  templateUrl: './backend-status.html',
  styleUrl: './backend-status.scss',
})
export class BackendStatus implements OnInit {
  private readonly api = inject(Api);

  protected readonly apiStatus = signal('Checking connection...');
  protected readonly health = signal<HealthResponse | null>(null);

  ngOnInit(): void {
    this.checkHealth();
  }

  protected checkHealth(): void {
    this.api.getHealth().subscribe({
      next: (response) => {
        this.health.set(response);
        this.apiStatus.set('Connected');
      },
      error: () => {
        this.health.set(null);
        this.apiStatus.set('Disconnected');
      },
    });
  }
}
