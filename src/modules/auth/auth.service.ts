import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { RefreshTokenService, DeviceInfo } from './services/refresh-token.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto, TokenResponseDto } from './dto/refresh-token.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly refreshTokenService: RefreshTokenService,
  ) { }

  async login(loginDto: LoginDto, deviceInfo?: DeviceInfo): Promise<TokenResponseDto> {
    const { email, password } = loginDto;

    const user = await this.usersService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const { accessToken, accessTokenExpiresAt } = this.generateAccessToken(user);
    const { token: refreshToken, expiresAt: refreshTokenExpiresAt } =
      await this.refreshTokenService.generateRefreshToken(user.id, deviceInfo);

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: accessTokenExpiresAt.toISOString(),
      refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
      tokenType: 'Bearer',
    };
  }

  async register(registerDto: RegisterDto, deviceInfo?: DeviceInfo): Promise<TokenResponseDto> {
    const existingUser = await this.usersService.findByEmail(registerDto.email);

    if (existingUser) {
      throw new UnauthorizedException('Email already exists');
    }

    const user = await this.usersService.create(registerDto);

    // Generate tokens for new user
    const { accessToken, accessTokenExpiresAt } = this.generateAccessToken(user);
    const { token: refreshToken, expiresAt: refreshTokenExpiresAt } =
      await this.refreshTokenService.generateRefreshToken(user.id, deviceInfo);

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: accessTokenExpiresAt.toISOString(),
      refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
      tokenType: 'Bearer',
    };
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<TokenResponseDto> {
    const { refreshToken } = refreshTokenDto;

    // Validate refresh token and get user ID
    const userId = await this.refreshTokenService.validateRefreshToken(refreshToken);
    const user = await this.usersService.findOne(userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Generate new access token
    const { accessToken, accessTokenExpiresAt } = this.generateAccessToken(user);

    // Generate new refresh token (token rotation for security)
    const { token: newRefreshToken, expiresAt: refreshTokenExpiresAt } =
      await this.refreshTokenService.generateRefreshToken(user.id);

    return {
      accessToken,
      refreshToken: newRefreshToken,
      accessTokenExpiresAt: accessTokenExpiresAt.toISOString(),
      refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
      tokenType: 'Bearer',
    };
  }

  /**
   * Logout user by revoking refresh token
   */
  async logout(refreshToken: string): Promise<void> {
    try {
      const userId = await this.refreshTokenService.validateRefreshToken(refreshToken);
      await this.refreshTokenService.revokeAllUserTokens(userId);
    } catch (error) {
      // Even if token is invalid, we consider logout successful
      // This prevents information leakage about token validity
    }
  }

  /**
   * Generate access token with expiration
   */
  private generateAccessToken(user: any): { accessToken: string; accessTokenExpiresAt: Date } {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role
    };

    const expiresIn = this.configService.get('JWT_EXPIRATION', '15m');
    const accessToken = this.jwtService.sign(payload);

    // Calculate expiration date
    const accessTokenExpiresAt = this.calculateTokenExpiration(expiresIn);

    return { accessToken, accessTokenExpiresAt };
  }

  /**
   * Calculate token expiration date
   */
  private calculateTokenExpiration(duration: string): Date {
    const now = new Date();
    const match = duration.match(/^(\d+)([dhm])$/);

    if (!match) {
      return new Date(now.getTime() + 15 * 60 * 1000); // Default 15 minutes
    }

    const [, value, unit] = match;
    const numValue = parseInt(value, 10);

    switch (unit) {
      case 'd':
        return new Date(now.getTime() + numValue * 24 * 60 * 60 * 1000);
      case 'h':
        return new Date(now.getTime() + numValue * 60 * 60 * 1000);
      case 'm':
        return new Date(now.getTime() + numValue * 60 * 1000);
      default:
        return new Date(now.getTime() + 15 * 60 * 1000);
    }
  }

  async validateUser(userId: string): Promise<any> {
    const user = await this.usersService.findOne(userId);

    if (!user) {
      return null;
    }

    return user;
  }

  async validateUserRoles(userId: string, requiredRoles: string[]): Promise<boolean> {
    if (!requiredRoles || requiredRoles.length === 0) {
      return true; // No specific roles required
    }

    const user = await this.usersService.findOne(userId);

    if (!user) {
      return false; // User not found
    }

    // Check if user has any of the required roles
    return requiredRoles.includes(user.role);
  }
} 