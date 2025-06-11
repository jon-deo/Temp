import { Injectable, NestMiddleware, BadRequestException, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ConfigService } from '@nestjs/config';

export interface RequestSizeLimitOptions {
  maxBodySize?: number;
  maxFileSize?: number;
  maxFiles?: number;
  allowedContentTypes?: string[];
}

@Injectable()
export class RequestSizeLimitMiddleware implements NestMiddleware {
  protected readonly logger = new Logger(RequestSizeLimitMiddleware.name);
  protected readonly defaultOptions: RequestSizeLimitOptions = {
    maxBodySize: 1024 * 1024, // 1MB
    maxFileSize: 5 * 1024 * 1024, // 5MB
    maxFiles: 10,
    allowedContentTypes: [
      'application/json',
      'application/x-www-form-urlencoded',
      'multipart/form-data',
      'text/plain',
    ],
  };

  constructor(
    protected readonly configService: ConfigService
  ) { }

  use(req: Request, res: Response, next: NextFunction) {
    const options = this.defaultOptions;

    // Check content type
    if (req.headers['content-type']) {
      const contentType = req.headers['content-type'].split(';')[0];
      if (options.allowedContentTypes &&
        !options.allowedContentTypes.some((allowed: string) => contentType.includes(allowed))) {
        this.logger.warn(`Blocked request with disallowed content type: ${contentType}`, {
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          path: req.path,
        });
        throw new BadRequestException('Content type not allowed');
      }
    }

    // Check content length
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > options.maxBodySize!) {
      this.logger.warn(`Blocked request exceeding body size limit: ${contentLength} bytes`, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        path: req.path,
        limit: options.maxBodySize,
      });
      throw new BadRequestException('Request body too large');
    }

    // For multipart/form-data, we'll validate file sizes in the controller
    // This middleware handles general request size limits

    // Add security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Set up request timeout
    const timeout = this.configService.get('REQUEST_TIMEOUT', 30000); // 30 seconds default
    req.setTimeout(timeout, () => {
      this.logger.warn('Request timeout', {
        ip: req.ip,
        path: req.path,
        timeout,
      });
      if (!res.headersSent) {
        res.status(408).json({
          statusCode: 408,
          message: 'Request timeout',
          error: 'Request Timeout',
        });
      }
    });

    next();
  }
}

// Factory function removed - use RequestSizeLimitMiddleware directly
// Custom options can be passed through constructor
