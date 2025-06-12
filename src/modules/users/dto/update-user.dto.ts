import { PartialType } from '@nestjs/swagger';
import { IsOptional, IsString, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { CreateUserDto } from './create-user.dto';

export class UpdateUserDto extends PartialType(CreateUserDto) {
    @ApiProperty({
        example: 'admin',
        description: 'User role (admin only)',
        enum: ['user', 'admin'],
        required: false
    })
    @IsOptional()
    @IsString()
    @IsIn(['user', 'admin'])
    role?: string;
}