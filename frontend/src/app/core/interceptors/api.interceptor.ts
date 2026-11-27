import { inject } from '@angular/core';

import { HttpInterceptorFn } from '@angular/common/http';

import { defer, finalize } from 'rxjs';

import { environment } from '../../../environments/environment';

import { LoadingService } from '../services/loading.service';

import { SKIP_GLOBAL_LOADING } from '../config/http-context';

export const apiInterceptor: HttpInterceptorFn = (request, next) => {
  const backendUrl = environment.apiBaseUrl.replace(/\/+$/, '');

  const isBackendRequest = request.url === backendUrl || request.url.startsWith(`${backendUrl}/`);

  if (!isBackendRequest) {
    return next(request);
  }

  const loading = inject(LoadingService);

  const trackLoading = !request.context.get(SKIP_GLOBAL_LOADING);

  return defer(() => {
    if (trackLoading) {
      loading.start();
    }

    return defer(() => next(request)).pipe(
      finalize(() => {
        if (trackLoading) {
          loading.stop();
        }
      }),
    );
  });
};
