import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({ 
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Refresh token to exchange for new access token'
  })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}

export class TokenResponseDto {
  @ApiProperty({ 
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'JWT access token'
  })
  accessToken: string;

  @ApiProperty({ 
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Refresh token for getting new access tokens'
  })
  refreshToken: string;

  @ApiProperty({ 
    example: '2024-01-01T00:00:00.000Z',
    description: 'Access token expiration time'
  })
  accessTokenExpiresAt: string;

  @ApiProperty({ 
    example: '2024-01-08T00:00:00.000Z',
    description: 'Refresh token expiration time'
  })
  refreshTokenExpiresAt: string;

  @ApiProperty({ 
    example: 'Bearer',
    description: 'Token type'
  })
  tokenType: string;
}
