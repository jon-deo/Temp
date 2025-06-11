import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Query, HttpException, HttpStatus } from '@nestjs/common';
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
    // ✅ OPTIMIZED: Service handles error throwing, no redundant check needed
    return this.tasksService.findOne(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a task' })
  @ApiResponse({ status: 200, description: 'Task updated successfully' })
  @ApiResponse({ status: 404, description: 'Task not found' })
  async update(@Param('id') id: string, @Body() updateTaskDto: UpdateTaskDto) {
    // ✅ OPTIMIZED: Service handles validation and error throwing
    return this.tasksService.update(id, updateTaskDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a task' })
  @ApiResponse({ status: 204, description: 'Task deleted successfully' })
  @ApiResponse({ status: 404, description: 'Task not found' })
  async remove(@Param('id') id: string) {
    // ✅ OPTIMIZED: Service handles validation and error throwing
    await this.tasksService.remove(id);
    // Return 204 No Content for successful deletion
    return;
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

      // ✅ OPTIMIZED: Use enhanced bulk operations with detailed results
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
        failed: result.failed.length,
        failedTaskIds: result.failed.length > 0 ? result.failed : undefined,
        successfulTaskIds: result.successful,
      };

    } catch (error) {
      // ✅ IMPROVED: Consistent error handling
      throw new HttpException(
        `Batch operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  @Post('bulk-create')
  @ApiOperation({ summary: 'Create multiple tasks in bulk' })
  @ApiResponse({
    status: 201,
    description: 'Bulk create operation completed',
  })
  async bulkCreate(@Body() createTaskDtos: CreateTaskDto[]) {
    try {
      const result = await this.tasksService.bulkCreate(createTaskDtos);

      return {
        success: true,
        message: `Successfully created ${result.created.length} tasks`,
        created: result.created.length,
        failed: result.failed.length,
        createdTasks: result.created,
        failedTasks: result.failed,
      };
    } catch (error) {
      throw new HttpException(
        `Bulk create failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  @Patch('bulk-update')
  @ApiOperation({ summary: 'Update multiple tasks with different data' })
  @ApiResponse({
    status: 200,
    description: 'Bulk update operation completed',
  })
  async bulkUpdate(@Body() updates: { id: string; data: Partial<UpdateTaskDto> }[]) {
    try {
      const result = await this.tasksService.bulkUpdate(updates);

      return {
        success: true,
        message: `Successfully updated ${result.updated.length} tasks`,
        updated: result.updated.length,
        failed: result.failed.length,
        updatedTaskIds: result.updated,
        failedUpdates: result.failed,
      };
    } catch (error) {
      throw new HttpException(
        `Bulk update failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}