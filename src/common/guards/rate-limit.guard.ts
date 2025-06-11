import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { RateLimitingService, RateLimitOptions } from '../services/rate-limiting.service';
import { RATE_LIMIT_KEY } from '../decorators/rate-limit.decorator';

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly rateLimitingService: RateLimitingService,
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get rate limit options from decorator metadata
    const rateLimitOptions = this.reflector.getAllAndOverride<RateLimitOptions>(
      RATE_LIMIT_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If no rate limiting is configured, allow the request
    if (!rateLimitOptions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Generate identifier for rate limiting
    const identifier = this.generateIdentifier(request);

    try {
      const result = await this.rateLimitingService.checkRateLimit(
        identifier,
        rateLimitOptions,
      );

      // Add rate limit headers to response
      this.addRateLimitHeaders(response, result);

      if (!result.allowed) {
        this.throwRateLimitException(result);
      }

      return true;
    } catch (error) {
      this.logger.error('Rate limiting error:', error);
      // In case of rate limiting service failure, allow the request
      // This prevents rate limiting from breaking the entire application
      return true;
    }
  }

  /**
   * Generate a secure identifier for rate limiting
   * Uses user ID if authenticated, otherwise falls back to IP
   */
  private generateIdentifier(request: any): string {
    // Prefer user ID for authenticated requests
    if (request.user && request.user.id) {
      return `user:${request.user.id}`;
    }

    // Fall back to IP address for anonymous requests
    // IP is hashed in the rate limiting service for privacy
    const ip = request.ip ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      'unknown';

    return `ip:${ip}`;
  }

  /**
   * Add standard rate limit headers to the response
   */
  private addRateLimitHeaders(response: any, result: any): void {
    response.setHeader('X-RateLimit-Limit', result.limit);
    response.setHeader('X-RateLimit-Remaining', result.remaining);
    response.setHeader('X-RateLimit-Reset', new Date(result.resetTime).toISOString());

    if (result.retryAfter) {
      response.setHeader('Retry-After', result.retryAfter);
    }
  }

  /**
   * Throw a secure rate limit exception without exposing sensitive data
   */
  private throwRateLimitException(result: any): void {
    throw new HttpException(
      {
        statusCode: HttpStatus.TOO_MANY_REQUESTS,
        message: 'Too many requests',
        error: 'Rate limit exceeded',
        // Only include safe, non-sensitive information
        retryAfter: result.retryAfter,
      },
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }
}