import {
  Component,
  OnInit,
  DestroyRef,
  inject,
  signal,
} from '@angular/core';

import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { timeout } from 'rxjs';

import { Api, HealthResponse } from '../../services/api';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-backend-status',
  standalone: true,
  templateUrl: './backend-status.html',
  styleUrl: './backend-status.scss',
})
export class BackendStatus implements OnInit {

  private readonly api = inject(Api);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly apiStatus = signal('Disconnected');

  protected readonly health =
    signal<HealthResponse | null>(null);

  ngOnInit(): void {
    this.checkHealth();
  }

  protected checkHealth(): void {

    if (this.apiStatus() === 'Checking connection...') {
      return;
    }

    this.apiStatus.set('Checking connection...');
    this.health.set(null);

    this.api.getHealth().pipe(
      timeout(environment.requestTimeoutMs),
      takeUntilDestroyed(this.destroyRef)
    ).subscribe({

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
