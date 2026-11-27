import {
  Injectable,
  signal,
} from '@angular/core';

import type {
  AppNotification,
  NotificationType,
} from '../models/notification.model';

@Injectable({
  providedIn: 'root',
})
export class NotificationService {

  private readonly items =
    signal<AppNotification[]>([]);

  readonly notifications =
    this.items.asReadonly();

  private readonly timers =
    new Map<string, ReturnType<typeof setTimeout>>();

  private sequence = 0;

  private readonly maxNotifications = 5;

  show(
    type: NotificationType,
    title: string,
    message: string,
    duration = 5000
  ): string {

    const existing = this.items().find(
      item =>
        item.type === type &&
        item.title === title &&
        item.message === message
    );

    if (existing) {
      return existing.id;
    }

    const id =
      `notification-${Date.now()}-${++this.sequence}`;

    const notification: AppNotification = {
      id,
      type,
      title,
      message,
      duration,
      createdAt: Date.now(),
    };

    while (
      this.items().length >= this.maxNotifications
    ) {
      this.dismiss(this.items()[0].id);
    }

    this.items.update(
      items => [...items, notification]
    );

    if (duration > 0) {

      const timer = setTimeout(
        () => this.dismiss(id),
        duration
      );

      this.timers.set(id, timer);

    }

    return id;

  }

  success(
    message: string,
    title = 'Success'
  ): string {

    return this.show(
      'success', title, message, 4000
    );

  }

  error(
    message: string,
    title = 'Error'
  ): string {

    return this.show(
      'error', title, message, 7000
    );

  }

  warning(
    message: string,
    title = 'Warning'
  ): string {

    return this.show(
      'warning', title, message, 6000
    );

  }

  info(
    message: string,
    title = 'Information'
  ): string {

    return this.show(
      'info', title, message, 5000
    );

  }

  dismiss(id: string): void {

    const timer = this.timers.get(id);

    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(id);
    }

    this.items.update(
      items => items.filter(item => item.id !== id)
    );

  }

  clear(): void {

    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }

    this.timers.clear();
    this.items.set([]);

  }

}
