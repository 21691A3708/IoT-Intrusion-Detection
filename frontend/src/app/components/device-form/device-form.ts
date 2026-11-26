import {
  Component,
  DestroyRef,
  inject,
  output,
  signal,
} from '@angular/core';

import { FormsModule } from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { finalize } from 'rxjs';

import {
  DeviceApiService,
} from '../../core/services/device-api.service';

import {
  NotificationService,
} from '../../core/services/notification.service';

import type {
  Device,
  DeviceCreate,
  DeviceStatus,
} from '../../core/models/device.model';

import {
  getApiErrorMessage,
} from '../../shared/utilities/api-error';

@Component({
  selector: 'app-device-form',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './device-form.html',
  styleUrl: './device-form.scss',
})
export class DeviceForm {

  private readonly api = inject(DeviceApiService);

  private readonly notifications =
    inject(NotificationService);

  private readonly destroyRef = inject(DestroyRef);

  readonly deviceRegistered = output<Device>();

  protected readonly savingDevice = signal(false);

  protected readonly deviceMessage = signal('');

  protected readonly deviceMessageType =
    signal<'success' | 'error'>('success');

  protected deviceName = '';
  protected deviceIdentifier = '';
  protected deviceType = 'temperature_sensor';
  protected deviceLocation = '';

  protected deviceStatus: DeviceStatus = 'unknown';

  protected registerDevice(): void {

    if (this.savingDevice()) {
      return;
    }

    this.deviceMessage.set('');

    const device: DeviceCreate = {

      device_name: this.deviceName.trim(),

      device_identifier: this.deviceIdentifier.trim(),

      device_type: this.deviceType.trim(),

      location: this.deviceLocation.trim() || null,

      status: this.deviceStatus,

    };

    if (
      !device.device_name ||
      !device.device_identifier ||
      !device.device_type
    ) {

      this.showError('Please complete all required fields.');

      return;

    }

    if (
      device.device_name.length > 150 ||
      device.device_identifier.length > 200 ||
      device.device_type.length > 100 ||
      (device.location?.length ?? 0) > 200
    ) {

      this.showError('One or more fields exceed the permitted length.');

      return;

    }

    const allowedStatuses: DeviceStatus[] = [
      'online',
      'offline',
      'unknown',
      'quarantined',
    ];

    if (!allowedStatuses.includes(device.status)) {

      this.showError('Invalid device status.');

      return;

    }

    this.savingDevice.set(true);

    this.api.registerDevice(device).pipe(

      takeUntilDestroyed(this.destroyRef),

      finalize(() => this.savingDevice.set(false))

    ).subscribe({

      next: createdDevice => {

        this.deviceMessageType.set('success');

        this.deviceMessage.set(
          `Device "${createdDevice.device_name}" registered successfully.`
        );

        this.notifications.success(
          'Device added to the registered inventory.',
          'Device registered'
        );

        this.resetForm();

        this.deviceRegistered.emit(createdDevice);

      },

      error: error => {

        if (
          error instanceof HttpErrorResponse &&
          error.status === 409
        ) {

          this.showError(
            'This device identifier already exists.'
          );

        } else {

          this.showError(getApiErrorMessage(error));

        }

      },

    });

  }

  private showError(message: string): void {

    this.deviceMessageType.set('error');
    this.deviceMessage.set(message);

  }

  private resetForm(): void {

    this.deviceName = '';
    this.deviceIdentifier = '';
    this.deviceType = 'temperature_sensor';
    this.deviceLocation = '';
    this.deviceStatus = 'unknown';

  }

}
