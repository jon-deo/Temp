import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ErrorSanitizationService } from '../services/error-sanitization.service';
import { QueryFailedError } from 'typeorm';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  constructor(private readonly errorSanitizationService: ErrorSanitizationService) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const { statusCode, errorResponse } = this.processException(exception, request.url);

    // Set security headers
    this.setSecurityHeaders(response);

    // Send sanitized error response
    response.status(statusCode).json(errorResponse);
  }

  /**
   * Process different types of exceptions and return sanitized response
   */
  private processException(exception: unknown, path: string): {
    statusCode: number;
    errorResponse: any;
  } {
    let statusCode: number;
    let originalError: any;

    // Handle different exception types
    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      originalError = exception;
    } else if (exception instanceof QueryFailedError) {
      // Database errors - always treat as internal server error
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
      originalError = this.sanitizeDatabaseError(exception);
    } else if (this.isValidationError(exception)) {
      statusCode = HttpStatus.BAD_REQUEST;
      originalError = this.sanitizeValidationError(exception);
    } else if (this.isAuthenticationError(exception)) {
      statusCode = HttpStatus.UNAUTHORIZED;
      originalError = { message: 'Authentication required' };
    } else if (this.isAuthorizationError(exception)) {
      statusCode = HttpStatus.FORBIDDEN;
      originalError = { message: 'Access denied' };
    } else {
      // Unknown errors - treat as internal server error
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
      originalError = exception;
    }

    // Sanitize the error for client response
    const errorResponse = this.errorSanitizationService.sanitizeError(
      originalError,
      statusCode,
      path,
    );

    return { statusCode, errorResponse };
  }

  /**
   * Sanitize database errors to prevent information leakage
   */
  private sanitizeDatabaseError(error: QueryFailedError): any {
    // Log the original database error for debugging
    this.logger.error('Database error occurred', {
      message: error.message,
      query: error.query,
      parameters: error.parameters,
      driverError: error.driverError,
    });

    // Return generic error for client
    return {
      message: 'A database operation failed',
      name: 'DatabaseError',
    };
  }

  /**
   * Sanitize validation errors to prevent field enumeration
   */
  private sanitizeValidationError(error: any): any {
    // Log original validation error
    this.logger.warn('Validation error occurred', {
      message: error.message,
      details: error.details || error.response,
    });

    // Return generic validation error
    return {
      message: 'Invalid input provided',
      name: 'ValidationError',
    };
  }

  /**
   * Check if error is a validation error
   */
  private isValidationError(exception: unknown): boolean {
    if (!exception || typeof exception !== 'object') return false;
    
    const error = exception as any;
    return (
      error.name === 'ValidationError' ||
      error.message?.includes('validation') ||
      error.message?.includes('invalid') ||
      (Array.isArray(error.response?.message) && error.status === 400)
    );
  }

  /**
   * Check if error is an authentication error
   */
  private isAuthenticationError(exception: unknown): boolean {
    if (!exception || typeof exception !== 'object') return false;
    
    const error = exception as any;
    return (
      error.name === 'UnauthorizedError' ||
      error.name === 'JsonWebTokenError' ||
      error.name === 'TokenExpiredError' ||
      error.message?.includes('unauthorized') ||
      error.message?.includes('token') ||
      error.message?.includes('authentication')
    );
  }

  /**
   * Check if error is an authorization error
   */
  private isAuthorizationError(exception: unknown): boolean {
    if (!exception || typeof exception !== 'object') return false;
    
    const error = exception as any;
    return (
      error.name === 'ForbiddenError' ||
      error.message?.includes('forbidden') ||
      error.message?.includes('access denied') ||
      error.message?.includes('permission')
    );
  }

  /**
   * Set security headers to prevent information leakage
   */
  private setSecurityHeaders(response: Response): void {
    // Remove server information
    response.removeHeader('X-Powered-By');
    
    // Add security headers
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Don't cache error responses
    response.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');
  }
}
