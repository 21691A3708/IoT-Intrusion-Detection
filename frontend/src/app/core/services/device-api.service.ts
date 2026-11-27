import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map, timeout } from 'rxjs';

import { environment } from '../../../environments/environment';
import { API_ENDPOINTS } from '../config/api-endpoints';

import type {
  Device,
  DeviceCreate,
  DeviceProfilesResponse,
} from '../models/device.model';

@Injectable({
  providedIn: 'root',
})
export class DeviceApiService {

  private readonly http = inject(HttpClient);

  getDevices(): Observable<Device[]> {

    return this.http.get<Device[]>(
      API_ENDPOINTS.devices.list
    ).pipe(
      timeout(environment.requestTimeoutMs),
      map(devices => {

        if (!Array.isArray(devices)) {
          throw new Error('Unexpected device registry response.');
        }

        return devices;

      })
    );

  }

  registerDevice(
    device: DeviceCreate
  ): Observable<Device> {

    return this.http.post<Device>(
      API_ENDPOINTS.devices.create,
      device
    ).pipe(
      timeout(environment.requestTimeoutMs)
    );

  }

  getDeviceProfiles(): Observable<DeviceProfilesResponse> {

    return this.http.get<DeviceProfilesResponse>(
      API_ENDPOINTS.devices.profiles
    ).pipe(
      timeout(environment.requestTimeoutMs),
      map(response => {

        if (
          !response ||
          response.mode !== 'demonstration_only' ||
          !Array.isArray(response.devices) ||
          response.total_devices !== response.devices.length
        ) {
          throw new Error('Unexpected device profiles response.');
        }

        const valid = response.devices.every(profile =>
          typeof profile.device_id === 'string' &&
          profile.device_id.length > 0 &&
          Number.isFinite(profile.criticality) &&
          profile.criticality >= 0 &&
          profile.criticality <= 1 &&
          Number.isFinite(profile.exposure) &&
          profile.exposure >= 0 &&
          profile.exposure <= 1 &&
          typeof profile.containment_allowed === 'boolean' &&
          profile.identity_verified === false &&
          profile.context_known === true &&
          profile.simulation_only === true
        );

        const uniqueIds = new Set(
          response.devices.map(profile => profile.device_id)
        );

        if (!valid || uniqueIds.size !== response.devices.length) {
          throw new Error('Invalid demonstration device profiles.');
        }

        return response;

      })
    );

  }

}
