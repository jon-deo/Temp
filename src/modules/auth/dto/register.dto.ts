import { IsEmail, IsNotEmpty, IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { IsStrongPassword, IsSafeText, IsBusinessEmail } from '../../../common/decorators/validation.decorators';

export class RegisterDto {
  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'Valid business email address (temporary emails not allowed)'
  })
  @IsEmail()
  @IsNotEmpty()
  @IsBusinessEmail()
  email: string;

  @ApiProperty({
    example: 'John Doe',
    description: 'Full name (2-100 characters, no HTML/scripts)'
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(100)
  @IsSafeText()
  name: string;

  @ApiProperty({
    example: 'MySecure123!',
    description: 'Strong password with uppercase, lowercase, number, and special character'
  })
  @IsString()
  @IsNotEmpty()
  @IsStrongPassword()
  password: string;
} 