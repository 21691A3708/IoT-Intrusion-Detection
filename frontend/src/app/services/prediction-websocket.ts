import { Injectable, NgZone, inject, signal } from '@angular/core';

import { Observable, defer, retry, shareReplay, timer } from 'rxjs';

export interface PredictionWebSocketEvent {
  event: string;
  data: {
    id: string;
    device_id: string | null;
    predicted_label: number;
    prediction: string;
    attack_probability: number;
    risk_level: string;
    source: string;
    created_at: string;
    incident_created: boolean;
    incident_id: string | null;
  };
}

export type WebSocketStatus = 'connecting' | 'connected' | 'reconnecting' | 'disconnected';

@Injectable({
  providedIn: 'root',
})
export class PredictionWebSocket {
  private readonly zone = inject(NgZone);

  private readonly socketUrl = 'ws://127.0.0.1:8000/ws/predictions';

  // Observable connection status for the dashboard
  readonly status = signal<WebSocketStatus>('disconnected');

  // Shared WebSocket event stream
  private readonly events$: Observable<PredictionWebSocketEvent> = defer(() => {
    this.setStatus('connecting');

    return new Observable<PredictionWebSocketEvent>((observer) => {
      let socket: WebSocket;

      try {
        socket = new WebSocket(this.socketUrl);
      } catch (error) {
        observer.error(error);

        return;
      }

      socket.onopen = () => {
        this.setStatus('connected');

        console.log('WebSocket connected successfully.');
      };

      socket.onmessage = (message) => {
        this.zone.run(() => {
          try {
            const event = JSON.parse(message.data) as PredictionWebSocketEvent;

            observer.next(event);
          } catch (error) {
            console.error('Invalid WebSocket message:', error);
          }
        });
      };

      socket.onerror = () => {
        this.setStatus('reconnecting');

        observer.error(new Error('WebSocket connection failed'));
      };

      socket.onclose = () => {
        this.setStatus('reconnecting');

        observer.error(new Error('WebSocket connection closed'));
      };

      // Clean up the socket when the last subscriber leaves
      return () => {
        socket.onopen = null;
        socket.onmessage = null;
        socket.onerror = null;
        socket.onclose = null;

        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
          socket.close();
        }
      };
    });
  }).pipe(
    // Automatically reconnect after connection failures
    retry({
      delay: (_error, retryCount) => {
        this.setStatus('reconnecting');

        const delay = Math.min(1000 * Math.pow(2, retryCount - 1), 15000);

        console.log(`WebSocket reconnecting in ${delay / 1000} seconds...`);

        return timer(delay);
      },
    }),

    // Share one WebSocket connection between all components
    shareReplay({
      bufferSize: 1,
      refCount: true,
    }),
  );

  // Components subscribe to the same connection
  connect(): Observable<PredictionWebSocketEvent> {
    return this.events$;
  }

  // Update connection status safely inside Angular
  private setStatus(status: WebSocketStatus): void {
    this.zone.run(() => {
      this.status.set(status);
    });
  }
}
