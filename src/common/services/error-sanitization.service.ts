import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface SanitizedError {
  statusCode: number;
  message: string;
  error: string;
  timestamp: string;
  path: string;
}

@Injectable()
export class ErrorSanitizationService {
  private readonly logger = new Logger(ErrorSanitizationService.name);
  private readonly isDevelopment: boolean;

  // Sensitive patterns to remove from error messages
  private readonly sensitivePatterns = [
    // Database-related terms
    /database/gi,
    /sql/gi,
    /query/gi,
    /table/gi,
    /column/gi,
    /constraint/gi,
    /relation/gi,
    /entity/gi,
    
    // File system paths
    /[a-zA-Z]:\\[^\\s]*/g, // Windows paths
    /\/[a-zA-Z0-9_\-\/.]*/g, // Unix paths (but keep simple ones)
    /src\/[^\\s]*/g, // Source code paths
    /node_modules\/[^\\s]*/g, // Node modules paths
    
    // Technology stack indicators
    /typeorm/gi,
    /nestjs/gi,
    /postgresql/gi,
    /redis/gi,
    /bullmq/gi,
    
    // Internal details
    /repository/gi,
    /service/gi,
    /controller/gi,
    /guard/gi,
    /strategy/gi,
    
    // Connection strings and credentials
    /password[=:][^\\s]*/gi,
    /token[=:][^\\s]*/gi,
    /secret[=:][^\\s]*/gi,
    /key[=:][^\\s]*/gi,
  ];

  // Generic error messages for different error types
  private readonly genericMessages = {
    validation: 'Invalid input provided',
    notFound: 'Resource not found',
    unauthorized: 'Authentication required',
    forbidden: 'Access denied',
    conflict: 'Resource already exists',
    internal: 'An internal error occurred',
    badRequest: 'Invalid request',
    timeout: 'Request timeout',
    tooManyRequests: 'Too many requests',
  };

  constructor(private readonly configService: ConfigService) {
    this.isDevelopment = this.configService.get('NODE_ENV') === 'development';
  }

  /**
   * Sanitize error for client response
   */
  sanitizeError(error: any, statusCode: number, path: string): SanitizedError {
    const timestamp = new Date().toISOString();
    
    // Log the original error for debugging (server-side only)
    this.logOriginalError(error, statusCode, path);

    // Determine safe message based on status code
    const safeMessage = this.getSafeMessage(error, statusCode);
    const safeErrorType = this.getSafeErrorType(statusCode);

    return {
      statusCode,
      message: safeMessage,
      error: safeErrorType,
      timestamp,
      path: this.sanitizePath(path),
    };
  }

  /**
   * Get safe error message based on status code and error type
   */
  private getSafeMessage(error: any, statusCode: number): string {
    // In development, show more details (but still sanitized)
    if (this.isDevelopment && error?.message) {
      return this.sanitizeMessage(error.message);
    }

    // In production, use generic messages
    switch (statusCode) {
      case 400:
        return this.genericMessages.badRequest;
      case 401:
        return this.genericMessages.unauthorized;
      case 403:
        return this.genericMessages.forbidden;
      case 404:
        return this.genericMessages.notFound;
      case 409:
        return this.genericMessages.conflict;
      case 422:
        return this.genericMessages.validation;
      case 429:
        return this.genericMessages.tooManyRequests;
      case 408:
        return this.genericMessages.timeout;
      case 500:
      default:
        return this.genericMessages.internal;
    }
  }

  /**
   * Get safe error type name
   */
  private getSafeErrorType(statusCode: number): string {
    switch (statusCode) {
      case 400:
        return 'Bad Request';
      case 401:
        return 'Unauthorized';
      case 403:
        return 'Forbidden';
      case 404:
        return 'Not Found';
      case 409:
        return 'Conflict';
      case 422:
        return 'Unprocessable Entity';
      case 429:
        return 'Too Many Requests';
      case 408:
        return 'Request Timeout';
      case 500:
      default:
        return 'Internal Server Error';
    }
  }

  /**
   * Sanitize error message by removing sensitive information
   */
  private sanitizeMessage(message: string): string {
    if (!message) return this.genericMessages.internal;

    let sanitized = message;

    // Remove sensitive patterns
    this.sensitivePatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    });

    // Remove potential IDs or sensitive data patterns
    sanitized = sanitized.replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '[ID]');
    sanitized = sanitized.replace(/\b\d{10,}\b/g, '[NUMBER]');

    // If message is too generic after sanitization, use generic message
    if (sanitized.length < 10 || sanitized.includes('[REDACTED]')) {
      return this.genericMessages.internal;
    }

    return sanitized;
  }

  /**
   * Sanitize request path to remove sensitive information
   */
  private sanitizePath(path: string): string {
    if (!path) return '/';

    // Remove query parameters that might contain sensitive data
    const cleanPath = path.split('?')[0];
    
    // Replace UUIDs and other IDs with generic placeholder
    return cleanPath.replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, ':id')
                   .replace(/\/\d+/g, '/:id');
  }

  /**
   * Log original error for debugging (server-side only)
   */
  private logOriginalError(error: any, statusCode: number, path: string): void {
    const errorInfo = {
      statusCode,
      path,
      message: error?.message,
      stack: error?.stack,
      name: error?.name,
      timestamp: new Date().toISOString(),
    };

    if (statusCode >= 500) {
      this.logger.error('Internal server error', errorInfo);
    } else if (statusCode >= 400) {
      this.logger.warn('Client error', errorInfo);
    } else {
      this.logger.debug('Error occurred', errorInfo);
    }
  }

  /**
   * Check if error contains sensitive information
   */
  isSensitiveError(error: any): boolean {
    if (!error?.message) return false;

    return this.sensitivePatterns.some(pattern => 
      pattern.test(error.message)
    );
  }
}
