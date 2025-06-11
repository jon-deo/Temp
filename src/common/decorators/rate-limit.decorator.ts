import { SetMetadata } from '@nestjs/common';

export const RATE_LIMIT_KEY = 'rate_limit';

export interface RateLimitOptions {
  limit: number;
  windowMs: number;
  keyGenerator?: (identifier: string) => string;
}

/**
 * Rate limiting decorator that works with RateLimitGuard
 * @param options Rate limiting configuration
 * @example
 * @RateLimit({ limit: 100, windowMs: 60000 }) // 100 requests per minute
 * @RateLimit({ limit: 5, windowMs: 60000 }) // 5 requests per minute
 */
export const RateLimit = (options: RateLimitOptions) => {
  return SetMetadata(RATE_LIMIT_KEY, options);
};