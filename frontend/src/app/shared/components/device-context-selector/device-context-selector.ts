import {
  Component,
  OnInit,
  inject,
  input,
} from '@angular/core';

import { DecimalPipe } from '@angular/common';

import {
  DeviceContextService,
} from '../../../core/services/device-context.service';

@Component({
  selector: 'app-device-context-selector',
  standalone: true,
  imports: [DecimalPipe],
  templateUrl: './device-context-selector.html',
  styleUrl: './device-context-selector.scss',
})
export class DeviceContextSelector implements OnInit {

  protected readonly context =
    inject(DeviceContextService);

  readonly disabled = input(false);

  ngOnInit(): void {

    this.context.loadProfiles();

  }

  protected changeContext(event: Event): void {

    if (this.disabled() || this.context.loading()) {
      return;
    }

    const select = event.target as HTMLSelectElement;

    const deviceId = select.value || null;

    const accepted = this.context.selectDevice(deviceId);

    if (!accepted) {

      select.value =
        this.context.selectedDeviceId() ?? '';

    }

  }

  protected clearContext(): void {

    if (!this.disabled() && !this.context.loading()) {

      this.context.clearSelection();

    }

  }

  protected refreshProfiles(): void {

    if (!this.disabled() && !this.context.loading()) {

      this.context.loadProfiles(true);

    }

  }

}
