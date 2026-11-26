import {
  Injectable,
  inject,
  signal,
  computed,
} from '@angular/core';

import { finalize } from 'rxjs';

import { DeviceApiService } from './device-api.service';

import type {
  DeviceContextProfile,
} from '../models/device.model';

import {
  getApiErrorMessage,
} from '../../shared/utilities/api-error';

@Injectable({
  providedIn: 'root',
})
export class DeviceContextService {

  private readonly api = inject(DeviceApiService);

  private readonly profileState =
    signal<DeviceContextProfile[]>([]);

  private readonly selectedIdState =
    signal<string | null>(null);

  private readonly loadingState = signal(false);

  private readonly loadedState = signal(false);

  private readonly errorState = signal('');

  readonly profiles = this.profileState.asReadonly();

  readonly selectedDeviceId =
    this.selectedIdState.asReadonly();

  readonly loading = this.loadingState.asReadonly();

  readonly loaded = this.loadedState.asReadonly();

  readonly error = this.errorState.asReadonly();

  readonly selectedProfile = computed(() => {

    const selectedId = this.selectedIdState();

    return this.profileState().find(
      profile => profile.device_id === selectedId
    ) ?? null;

  });

  readonly totalProfiles = computed(
    () => this.profileState().length
  );

  readonly restrictedProfiles = computed(
    () => this.profileState().filter(
      profile => !profile.containment_allowed
    ).length
  );

  readonly verifiedProfiles = computed(
    () => this.profileState().filter(
      profile => profile.identity_verified
    ).length
  );

  loadProfiles(force = false): void {

    if (
      this.loadingState() ||
      (this.loadedState() && !force)
    ) {
      return;
    }

    this.loadingState.set(true);
    this.errorState.set('');

    this.api.getDeviceProfiles().pipe(

      finalize(() => this.loadingState.set(false))

    ).subscribe({

      next: response => {

        this.profileState.set(response.devices);
        this.loadedState.set(true);

        const selectedId = this.selectedIdState();

        if (
          selectedId !== null &&
          !response.devices.some(
            profile => profile.device_id === selectedId
          )
        ) {
          this.selectedIdState.set(null);
        }

      },

      error: error => {

        this.profileState.set([]);
        this.selectedIdState.set(null);
        this.loadedState.set(false);

        this.errorState.set(
          getApiErrorMessage(error)
        );

      },

    });

  }

  selectDevice(deviceId: string | null): boolean {

    if (deviceId === null) {

      this.selectedIdState.set(null);

      return true;

    }

    if (
      this.loadingState() ||
      !this.loadedState() ||
      !this.profileState().some(
        profile => profile.device_id === deviceId
      )
    ) {
      return false;
    }

    this.selectedIdState.set(deviceId);

    return true;

  }

  clearSelection(): void {

    this.selectedIdState.set(null);

  }

}
