import { Body, Controller, Post, Req, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto, TokenResponseDto } from './dto/refresh-token.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Request } from 'express';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('login')
  @ApiOperation({ summary: 'Login user and get access/refresh tokens' })
  @ApiResponse({ status: 200, description: 'Login successful', type: TokenResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto, @Req() request: Request): Promise<TokenResponseDto> {
    const deviceInfo = {
      userAgent: request.headers['user-agent'],
      ipAddress: request.ip,
    };
    return this.authService.login(loginDto, deviceInfo);
  }

  @Post('register')
  @ApiOperation({ summary: 'Register new user and get access/refresh tokens' })
  @ApiResponse({ status: 201, description: 'Registration successful', type: TokenResponseDto })
  @ApiResponse({ status: 400, description: 'Email already exists' })
  async register(@Body() registerDto: RegisterDto, @Req() request: Request): Promise<TokenResponseDto> {
    const deviceInfo = {
      userAgent: request.headers['user-agent'],
      ipAddress: request.ip,
    };
    return this.authService.register(registerDto, deviceInfo);
  }

  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully', type: TokenResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto): Promise<TokenResponseDto> {
    return this.authService.refreshToken(refreshTokenDto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Logout user and revoke refresh token' })
  @ApiResponse({ status: 204, description: 'Logout successful' })
  async logout(@Body() refreshTokenDto: RefreshTokenDto): Promise<void> {
    await this.authService.logout(refreshTokenDto.refreshToken);
  }
}