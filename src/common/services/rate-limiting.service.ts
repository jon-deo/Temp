import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'crypto';

export interface RateLimitOptions {
  limit: number;
  windowMs: number;
  keyGenerator?: (identifier: string) => string;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

@Injectable()
export class RateLimitingService {
  private readonly logger = new Logger(RateLimitingService.name);
  private readonly cache = new Map<string, { count: number; resetTime: number }>();
  private readonly cleanupInterval: NodeJS.Timeout;

  constructor(private readonly configService: ConfigService) {
    // Cleanup expired entries every 5 minutes to prevent memory leaks
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredEntries();
    }, 5 * 60 * 1000);
  }

  /**
   * Check if a request should be rate limited
   * @param identifier - User identifier (IP, user ID, etc.)
   * @param options - Rate limiting options
   * @returns Rate limit result
   */
  async checkRateLimit(
    identifier: string,
    options: RateLimitOptions,
  ): Promise<RateLimitResult> {
    const key = this.generateSecureKey(identifier, options);
    const now = Date.now();
    const windowStart = now - options.windowMs;

    // Get or create rate limit entry
    let entry = this.cache.get(key);

    // Reset if window has expired
    if (!entry || entry.resetTime <= now) {
      entry = {
        count: 0,
        resetTime: now + options.windowMs,
      };
    }

    // Check if limit is exceeded
    if (entry.count >= options.limit) {
      const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
      
      this.logger.warn(`Rate limit exceeded for key: ${this.hashKey(key)}`);
      
      return {
        allowed: false,
        limit: options.limit,
        remaining: 0,
        resetTime: entry.resetTime,
        retryAfter,
      };
    }

    // Increment counter
    entry.count++;
    this.cache.set(key, entry);

    return {
      allowed: true,
      limit: options.limit,
      remaining: Math.max(0, options.limit - entry.count),
      resetTime: entry.resetTime,
    };
  }

  /**
   * Generate a secure, hashed key for rate limiting
   * Prevents key enumeration and protects user privacy
   */
  private generateSecureKey(identifier: string, options: RateLimitOptions): string {
    const salt = this.configService.get('RATE_LIMIT_SALT', 'default-salt');
    const baseKey = options.keyGenerator 
      ? options.keyGenerator(identifier)
      : `${identifier}:${options.limit}:${options.windowMs}`;
    
    // Hash the key to prevent enumeration and protect privacy
    return createHash('sha256')
      .update(`${salt}:${baseKey}`)
      .digest('hex');
  }

  /**
   * Create a short hash for logging (privacy-safe)
   */
  private hashKey(key: string): string {
    return createHash('sha256').update(key).digest('hex').substring(0, 8);
  }

  /**
   * Clean up expired entries to prevent memory leaks
   */
  private cleanupExpiredEntries(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.resetTime <= now) {
        this.cache.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      this.logger.debug(`Cleaned up ${cleanedCount} expired rate limit entries`);
    }
  }

  /**
   * Get current cache size (for monitoring)
   */
  getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Clear all rate limit entries (for testing)
   */
  clearAll(): void {
    this.cache.clear();
    this.logger.debug('Cleared all rate limit entries');
  }

  /**
   * Cleanup on service destruction
   */
  onModuleDestroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}
