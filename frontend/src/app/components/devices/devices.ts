import {
  Component,
  OnInit,
  input,
  inject,
  signal,
  computed,
} from '@angular/core';

import { DatePipe, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import type { Device } from '../../core/models/device.model';

import {
  DeviceContextService,
} from '../../core/services/device-context.service';

@Component({
  selector: 'app-devices',
  standalone: true,
  imports: [DatePipe, DecimalPipe, FormsModule],
  templateUrl: './devices.html',
  styleUrl: './devices.scss',
})
export class Devices implements OnInit {

  readonly devices = input.required<Device[]>();
  readonly loading = input(false);
  readonly error = input('');

  protected readonly context = inject(DeviceContextService);

  protected readonly search = signal('');
  protected readonly statusFilter = signal('all');

  protected readonly onlineCount = computed(() =>
    this.devices().filter(
      device => device.status === 'online'
    ).length
  );

  protected readonly filteredDevices = computed(() => {

    const query = this.search().trim().toLowerCase();
    const status = this.statusFilter();

    return this.devices().filter(device => {

      const searchable = [
        device.device_name,
        device.device_identifier,
        device.device_type,
        device.location ?? '',
      ].join(' ').toLowerCase();

      return searchable.includes(query) &&
        (status === 'all' || device.status === status);

    });

  });

  ngOnInit(): void {
    this.context.loadProfiles();
  }

  protected resetFilters(): void {
    this.search.set('');
    this.statusFilter.set('all');
  }

}
