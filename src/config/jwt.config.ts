import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET environment variable is required for security');
  }

  if (secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long for security');
  }

  return {
    secret,
    expiresIn: process.env.JWT_EXPIRATION || '15m', // Shorter expiration for security
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d',
  };
});