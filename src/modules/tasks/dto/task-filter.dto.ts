import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsEnum, IsInt, Min, Max, IsString } from 'class-validator';
import { Type } from 'class-transformer';
import { TaskStatus } from '../enums/task-status.enum';
import { TaskPriority } from '../enums/task-priority.enum';

export class TaskFilterDto {
  @ApiProperty({
    enum: TaskStatus,
    required: false,
    description: 'Filter tasks by status'
  })
  @IsOptional()
  @IsEnum(TaskStatus)
  status?: TaskStatus;

  @ApiProperty({
    enum: TaskPriority,
    required: false,
    description: 'Filter tasks by priority'
  })
  @IsOptional()
  @IsEnum(TaskPriority)
  priority?: TaskPriority;

  @ApiProperty({
    example: 1,
    minimum: 1,
    required: false,
    description: 'Page number (starts from 1)'
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiProperty({
    example: 10,
    minimum: 1,
    maximum: 100,
    required: false,
    description: 'Number of items per page (1-100)'
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 10;

  @ApiProperty({
    example: 'title',
    required: false,
    description: 'Sort by field (title, status, priority, createdAt, dueDate)'
  })
  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiProperty({
    example: 'DESC',
    required: false,
    description: 'Sort order (ASC or DESC)'
  })
  @IsOptional()
  @IsString()
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}

export class PaginatedTaskResponseDto {
  @ApiProperty({
    description: 'Array of tasks',
    type: 'array'
  })
  data: any[];

  @ApiProperty({
    example: 25,
    description: 'Total number of tasks matching the filter'
  })
  total: number;

  @ApiProperty({
    example: 1,
    description: 'Current page number'
  })
  page: number;

  @ApiProperty({
    example: 10,
    description: 'Number of items per page'
  })
  limit: number;

  @ApiProperty({
    example: 3,
    description: 'Total number of pages'
  })
  totalPages: number;

  @ApiProperty({
    example: true,
    description: 'Whether there is a next page'
  })
  hasNext: boolean;

  @ApiProperty({
    example: false,
    description: 'Whether there is a previous page'
  })
  hasPrev: boolean;
}