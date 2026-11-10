import { Component, inject, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, Device, DeviceCreate } from '../../services/api';

@Component({
  selector: 'app-device-form',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './device-form.html',
  styleUrl: './device-form.scss',
})
export class DeviceForm {
  private readonly api = inject(Api);

  readonly deviceRegistered = output<Device>();

  protected readonly savingDevice = signal(false);
  protected readonly deviceMessage = signal('');
  protected readonly deviceMessageType = signal<'success' | 'error'>('success');

  protected deviceName = '';
  protected deviceIdentifier = '';
  protected deviceType = 'temperature_sensor';
  protected deviceLocation = '';
  protected deviceStatus: DeviceCreate['status'] = 'online';

  protected registerDevice(): void {
    this.deviceMessage.set('');

    const device: DeviceCreate = {
      device_name: this.deviceName.trim(),
      device_identifier: this.deviceIdentifier.trim(),
      device_type: this.deviceType.trim(),
      location: this.deviceLocation.trim(),
      status: this.deviceStatus,
    };

    if (!device.device_name || !device.device_identifier || !device.device_type) {
      this.showError('Please complete all required fields.');
      return;
    }

    this.savingDevice.set(true);

    this.api.createDevice(device).subscribe({
      next: (createdDevice) => {
        this.deviceMessageType.set('success');
        this.deviceMessage.set(`Device "${createdDevice.device_name}" registered successfully.`);

        this.resetForm();
        this.savingDevice.set(false);

        // Notify Dashboard that a device was registered.
        this.deviceRegistered.emit(createdDevice);
      },

      error: (error) => {
        if (error.status === 409) {
          this.showError('That device identifier already exists. Please use a unique identifier.');
        } else if (error.status === 422) {
          this.showError('The server rejected the device details. Check the required fields.');
        } else {
          this.showError('Could not register the device. Check the backend and try again.');
        }

        this.savingDevice.set(false);
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
    this.deviceStatus = 'online';
  }
}
