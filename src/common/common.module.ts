import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CacheService } from './services/cache.service';
import { RateLimitingService } from './services/rate-limiting.service';

@Module({
  imports: [ConfigModule],
  providers: [
    CacheService,
    RateLimitingService,
  ],
  exports: [
    CacheService,
    RateLimitingService,
  ],
})
export class CommonModule {}
