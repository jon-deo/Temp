import { IsArray, IsEnum, IsNotEmpty, IsString, ArrayMinSize, ArrayMaxSize } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum BatchAction {
  COMPLETE = 'complete',
  DELETE = 'delete',
}

export class BatchOperationDto {
  @ApiProperty({
    example: ['660e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001'],
    description: 'Array of task IDs to process (1-100 tasks)',
    type: [String]
  })
  @IsArray()
  @IsString({ each: true })
  @IsNotEmpty({ each: true })
  @ArrayMinSize(1, { message: 'At least one task ID is required' })
  @ArrayMaxSize(100, { message: 'Maximum 100 tasks can be processed at once' })
  tasks: string[];

  @ApiProperty({
    enum: BatchAction,
    example: BatchAction.COMPLETE,
    description: 'Action to perform on the tasks'
  })
  @IsEnum(BatchAction, { message: 'Action must be either "complete" or "delete"' })
  @IsNotEmpty()
  action: BatchAction;
}

export class BatchOperationResponseDto {
  @ApiProperty({
    example: true,
    description: 'Whether the batch operation was successful'
  })
  success: boolean;

  @ApiProperty({
    example: 'Successfully completed 5 tasks',
    description: 'Human-readable message about the operation result'
  })
  message: string;

  @ApiProperty({
    example: 5,
    description: 'Number of tasks successfully processed'
  })
  processed: number;

  @ApiProperty({
    example: 0,
    description: 'Number of tasks that failed to process'
  })
  failed: number;

  @ApiProperty({
    example: ['660e8400-e29b-41d4-a716-446655440000'],
    description: 'Array of task IDs that failed to process (if any)',
    required: false,
    type: [String]
  })
  failedTaskIds?: string[];
}
