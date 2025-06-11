import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CacheService } from './services/cache.service';
import { RateLimitingService } from './services/rate-limiting.service';
import { ErrorSanitizationService } from './services/error-sanitization.service';
import { GlobalExceptionFilter } from './filters/global-exception.filter';

@Module({
  imports: [ConfigModule],
  providers: [
    CacheService,
    RateLimitingService,
    ErrorSanitizationService,
    GlobalExceptionFilter,
  ],
  exports: [
    CacheService,
    RateLimitingService,
    ErrorSanitizationService,
    GlobalExceptionFilter,
  ],
})
export class CommonModule { }
