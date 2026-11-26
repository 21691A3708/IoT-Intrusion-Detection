import {
  HttpErrorResponse,
} from '@angular/common/http';

import { TimeoutError } from 'rxjs';

export function getApiErrorMessage(
  error: unknown
): string {

  if (error instanceof TimeoutError) {

    return 'The request timed out. Check the operation status before retrying.';

  }

  if (!(error instanceof HttpErrorResponse)) {

    return 'An unexpected application error occurred.';

  }

  switch (error.status) {

    case 0:
      return 'Unable to reach the backend. Check your connection and backend service.';

    case 400:
      return 'The request contains invalid data.';

    case 401:
      return 'Authentication is required.';

    case 403:
      return 'You are not authorized to perform this operation.';

    case 404:
      return 'The requested resource could not be found.';

    case 409:
      return 'The operation conflicts with the current resource state. Refresh and try again.';

    case 413:
      return 'The uploaded file exceeds the allowed size.';

    case 422:
      return 'Validation failed. Check the required input fields and values.';

    case 429:
      return 'Too many requests. Please try again later.';

    case 500:
      return 'An internal backend error occurred.';

    case 502:
    case 503:
    case 504:
      return 'The backend service is temporarily unavailable.';

    default:
      return `Request failed with HTTP status ${error.status}.`;

  }

}
