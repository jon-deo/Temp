import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Query, HttpException, HttpStatus, UseInterceptors } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { BatchOperationDto, BatchOperationResponseDto, BatchAction } from './dto/batch-operation.dto';
import { TaskFilterDto, PaginatedTaskResponseDto } from './dto/task-filter.dto';
import { ApiBearerAuth, ApiOperation, ApiTags, ApiResponse } from '@nestjs/swagger';
import { TaskStatus } from './enums/task-status.enum';
import { RateLimitGuard } from '../../common/guards/rate-limit.guard';
import { RateLimit } from '../../common/decorators/rate-limit.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('tasks')
@Controller('tasks')
@UseGuards(JwtAuthGuard, RateLimitGuard)
@RateLimit({ limit: 100, windowMs: 60000 })
@ApiBearerAuth()
export class TasksController {
  constructor(
    private readonly tasksService: TasksService,
    // ✅ OPTIMIZED: Removed direct repository access, using service layer properly
  ) { }

  @Post()
  @ApiOperation({ summary: 'Create a new task' })
  create(@Body() createTaskDto: CreateTaskDto) {
    return this.tasksService.create(createTaskDto);
  }

  @Get()
  @ApiOperation({ summary: 'Find all tasks with optional filtering and pagination' })
  @ApiResponse({
    status: 200,
    description: 'Tasks retrieved successfully with pagination',
    type: PaginatedTaskResponseDto
  })
  async findAll(@Query() filters: TaskFilterDto): Promise<PaginatedTaskResponseDto> {
    // ✅ OPTIMIZED: Database-level filtering and pagination instead of memory operations
    return this.tasksService.findAllWithFilters(filters);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get task statistics' })
  async getStats() {
    // ✅ OPTIMIZED: Use SQL aggregation instead of loading all tasks into memory
    return this.tasksService.getTaskStatistics();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Find a task by ID' })
  async findOne(@Param('id') id: string) {
    const task = await this.tasksService.findOne(id);

    if (!task) {
      // Inefficient error handling: Revealing internal details
      throw new HttpException(`Task with ID ${id} not found in the database`, HttpStatus.NOT_FOUND);
    }

    return task;
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a task' })
  update(@Param('id') id: string, @Body() updateTaskDto: UpdateTaskDto) {
    // No validation if task exists before update
    return this.tasksService.update(id, updateTaskDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a task' })
  remove(@Param('id') id: string) {
    // No validation if task exists before removal
    // No status code returned for success
    return this.tasksService.remove(id);
  }

  @Post('batch')
  @ApiOperation({ summary: 'Batch process multiple tasks' })
  @ApiResponse({
    status: 200,
    description: 'Batch operation completed successfully',
    type: BatchOperationResponseDto
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input or validation error'
  })
  async batchProcess(@Body() batchOperation: BatchOperationDto): Promise<BatchOperationResponseDto> {
    const { tasks: taskIds, action } = batchOperation;

    try {
      // ✅ OPTIMIZED: Validate all tasks exist in a single query
      const { existing, missing } = await this.tasksService.validateTasksExist(taskIds);

      if (missing.length > 0) {
        return {
          success: false,
          message: `Tasks not found: ${missing.join(', ')}`,
          processed: 0,
          failed: missing.length,
          failedTaskIds: missing
        };
      }

      // ✅ OPTIMIZED: Use bulk operations instead of N+1 queries
      let result;
      switch (action) {
        case BatchAction.COMPLETE:
          result = await this.tasksService.bulkUpdateStatus(existing, TaskStatus.COMPLETED);
          break;
        case BatchAction.DELETE:
          result = await this.tasksService.bulkDelete(existing);
          break;
        default:
          throw new HttpException(`Unknown action: ${action}`, HttpStatus.BAD_REQUEST);
      }

      return {
        success: true,
        message: `Successfully ${action}d ${result.affected} tasks`,
        processed: result.affected,
        failed: 0
      };

    } catch (error) {
      // ✅ IMPROVED: Consistent error handling
      throw new HttpException(
        `Batch operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
} 