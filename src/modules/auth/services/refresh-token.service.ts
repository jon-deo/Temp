import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { RefreshToken } from '../entities/refresh-token.entity';
import { createHash, randomBytes } from 'crypto';

export interface RefreshTokenData {
  token: string;
  expiresAt: Date;
}

export interface DeviceInfo {
  userAgent?: string;
  ipAddress?: string;
}

@Injectable()
export class RefreshTokenService {
  private readonly logger = new Logger(RefreshTokenService.name);

  constructor(
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    private configService: ConfigService,
  ) { }

  /**
   * Generate a new refresh token for a user
   */
  async generateRefreshToken(
    userId: string,
    deviceInfo?: DeviceInfo,
  ): Promise<RefreshTokenData> {
    // Generate a cryptographically secure random token
    const token = this.generateSecureToken();
    const tokenHash = this.hashToken(token);

    // Calculate expiration time
    const expirationDays = this.configService.get('JWT_REFRESH_EXPIRATION', '7d');
    const expiresAt = this.calculateExpirationDate(expirationDays);

    // Create refresh token entity
    const refreshToken = new RefreshToken();
    refreshToken.tokenHash = tokenHash;
    refreshToken.userId = userId;
    refreshToken.expiresAt = expiresAt;
    refreshToken.deviceInfo = deviceInfo?.userAgent;
    refreshToken.ipAddress = deviceInfo?.ipAddress;

    await this.refreshTokenRepository.save(refreshToken);

    this.logger.debug(`Generated refresh token for user ${userId}`);

    return {
      token,
      expiresAt,
    };
  }

  /**
   * Validate and consume a refresh token
   */
  async validateRefreshToken(token: string): Promise<string> {
    const tokenHash = this.hashToken(token);

    const refreshToken = await this.refreshTokenRepository.findOne({
      where: {
        tokenHash,
        isRevoked: false,
      },
      relations: ['user'],
    });

    if (!refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (refreshToken.expiresAt < new Date()) {
      // Clean up expired token
      await this.revokeRefreshToken(refreshToken.id);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Update last used timestamp
    refreshToken.lastUsedAt = new Date();
    await this.refreshTokenRepository.save(refreshToken);

    this.logger.debug(`Validated refresh token for user ${refreshToken.userId}`);

    return refreshToken.userId;
  }

  /**
   * Revoke a specific refresh token
   */
  async revokeRefreshToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepository.update(
      { id: tokenId },
      { isRevoked: true },
    );

    this.logger.debug(`Revoked refresh token ${tokenId}`);
  }

  /**
   * Revoke all refresh tokens for a user
   */
  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.refreshTokenRepository.update(
      { userId, isRevoked: false },
      { isRevoked: true },
    );

    this.logger.debug(`Revoked all refresh tokens for user ${userId}`);
  }

  /**
   * Clean up expired refresh tokens
   */
  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.refreshTokenRepository.delete({
      expiresAt: LessThan(new Date()),
    });

    const deletedCount = result.affected || 0;

    if (deletedCount > 0) {
      this.logger.debug(`Cleaned up ${deletedCount} expired refresh tokens`);
    }

    return deletedCount;
  }

  /**
   * Get active refresh tokens for a user (for security monitoring)
   */
  async getUserActiveTokens(userId: string): Promise<RefreshToken[]> {
    return this.refreshTokenRepository.find({
      where: {
        userId,
        isRevoked: false,
      },
      select: ['id', 'deviceInfo', 'ipAddress', 'createdAt', 'lastUsedAt'],
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Generate a cryptographically secure token
   */
  private generateSecureToken(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Hash a token for secure storage
   */
  private hashToken(token: string): string {
    const salt = this.configService.get('JWT_SECRET', 'fallback-salt');
    return createHash('sha256').update(`${salt}:${token}`).digest('hex');
  }

  /**
   * Calculate expiration date from duration string
   */
  private calculateExpirationDate(duration: string): Date {
    const now = new Date();

    // Parse duration (e.g., "7d", "24h", "30m")
    const match = duration.match(/^(\d+)([dhm])$/);
    if (!match) {
      // Default to 7 days if parsing fails
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    }

    const [, value, unit] = match;
    const numValue = parseInt(value, 10);

    switch (unit) {
      case 'd': // days
        return new Date(now.getTime() + numValue * 24 * 60 * 60 * 1000);
      case 'h': // hours
        return new Date(now.getTime() + numValue * 60 * 60 * 1000);
      case 'm': // minutes
        return new Date(now.getTime() + numValue * 60 * 1000);
      default:
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    }
  }
}
