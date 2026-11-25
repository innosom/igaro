export class AppError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/** 429 with a Retry-After header (set by the error handler). */
export class RateLimitedError extends AppError {
  constructor(readonly retryAfterSeconds: number) {
    super(429, 'RATE_LIMITED', 'Too many requests');
  }
}

/** Unknown id or another tenant's id. Always 404, never 403, so existence is not revealed. */
export class NotFoundError extends AppError {
  constructor(message = 'Not found') {
    super(404, 'NOT_FOUND', message);
  }
}
