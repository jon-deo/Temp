import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Query, HttpException, HttpStatus, ForbiddenException } from '@nestjs/common';
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
import { QueryPerformanceService } from '../../common/services/query-performance.service';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@ApiTags('tasks')
@Controller('tasks')
@UseGuards(JwtAuthGuard, RateLimitGuard)
@RateLimit({ limit: 100, windowMs: 60000 })
@ApiBearerAuth()
export class TasksController {
  constructor(
    private readonly tasksService: TasksService,
    private readonly queryPerformanceService: QueryPerformanceService,
    // ✅ OPTIMIZED: Removed direct repository access, using service layer properly
  ) { }

  @Post()
  @ApiOperation({ summary: 'Create a new task' })
  create(@Body() createTaskDto: CreateTaskDto, @CurrentUser() user: any) {
    // ✅ AUTHORIZATION: Only admin can assign tasks to others
    if (createTaskDto.userId && user.role !== 'admin' && createTaskDto.userId !== user.id) {
      throw new ForbiddenException('You can only create tasks for yourself');
    }

    return this.tasksService.create(createTaskDto, user.id);
  }

  @Get()
  @ApiOperation({ summary: 'Find all tasks with optional filtering and pagination' })
  @ApiResponse({
    status: 200,
    description: 'Tasks retrieved successfully with pagination',
    type: PaginatedTaskResponseDto
  })
  async findAll(@Query() filters: TaskFilterDto, @CurrentUser() user: any): Promise<PaginatedTaskResponseDto> {
    // ✅ AUTHORIZATION: Users can only see their own tasks, admins see all
    const userFilters = user.role === 'admin' ? filters : { ...filters, userId: user.id };

    // ✅ OPTIMIZED: Database-level filtering and pagination instead of memory operations
    return this.tasksService.findAllWithFilters(userFilters);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get task statistics' })
  async getStats(@CurrentUser() user: any) {
    // ✅ AUTHORIZATION: Users see stats for their tasks only, admins see all
    return this.tasksService.getTaskStatistics(user.id, user.role);
  }

  @Get('performance')
  @ApiOperation({ summary: 'Get database performance metrics and index usage' })
  @ApiResponse({
    status: 200,
    description: 'Performance metrics retrieved successfully'
  })
  async getPerformanceMetrics() {
    try {
      // ✅ MONITORING: Get comprehensive performance metrics
      const [indexUsage, tableStats, slowQueries] = await Promise.all([
        this.queryPerformanceService.checkIndexUsage(),
        this.queryPerformanceService.getTableStats(),
        this.queryPerformanceService.analyzeSlowQueries(),
      ]);

      return {
        success: true,
        timestamp: new Date().toISOString(),
        metrics: {
          indexUsage,
          tableStats,
          slowQueries,
        },
        summary: {
          indexesActive: indexUsage.indexStats.filter(stat => stat.idx_scan > 0).length,
          totalIndexes: indexUsage.indexStats.length,
          tableSize: tableStats.tableSize,
          rowCount: tableStats.rowCount,
        }
      };
    } catch (error) {
      throw new HttpException(
        `Failed to get performance metrics: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  @Get(':id')
  @ApiOperation({ summary: 'Find a task by ID' })
  async findOne(@Param('id') id: string, @CurrentUser() user: any) {
    // ✅ AUTHORIZATION: Check ownership at service level
    return this.tasksService.findOne(id, user.id, user.role);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a task' })
  @ApiResponse({ status: 200, description: 'Task updated successfully' })
  @ApiResponse({ status: 404, description: 'Task not found' })
  async update(@Param('id') id: string, @Body() updateTaskDto: UpdateTaskDto, @CurrentUser() user: any) {
    // ✅ AUTHORIZATION: Check ownership at service level
    return this.tasksService.update(id, updateTaskDto, user.id, user.role);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a task' })
  @ApiResponse({ status: 204, description: 'Task deleted successfully' })
  @ApiResponse({ status: 404, description: 'Task not found' })
  async remove(@Param('id') id: string, @CurrentUser() user: any) {
    // ✅ AUTHORIZATION: Check ownership at service level
    await this.tasksService.remove(id, user.id, user.role);
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
  async batchProcess(@Body() batchOperation: BatchOperationDto, @CurrentUser() user: any): Promise<BatchOperationResponseDto> {
    const { tasks: taskIds, action } = batchOperation;

    try {
      // ✅ AUTHORIZATION: Validate user can access these tasks
      const { existing, missing } = await this.tasksService.validateTasksExist(taskIds, user.id, user.role);

      if (missing.length > 0) {
        return {
          success: false,
          message: `Tasks not found or access denied: ${missing.join(', ')}`,
          processed: 0,
          failed: missing.length,
          failedTaskIds: missing
        };
      }

      // ✅ OPTIMIZED: Use enhanced bulk operations with detailed results
      let result;
      switch (action) {
        case BatchAction.COMPLETE:
          result = await this.tasksService.bulkUpdateStatus(existing, TaskStatus.COMPLETED, user.id, user.role);
          break;
        case BatchAction.DELETE:
          result = await this.tasksService.bulkDelete(existing, user.id, user.role);
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
  async bulkCreate(@Body() createTaskDtos: CreateTaskDto[], @CurrentUser() user: any) {
    try {
      // ✅ AUTHORIZATION: Add userId to all tasks
      const tasksWithUser = createTaskDtos.map(dto => ({ ...dto, userId: user.id }));
      const result = await this.tasksService.bulkCreate(tasksWithUser);

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
  async bulkUpdate(@Body() updates: { id: string; data: Partial<UpdateTaskDto> }[], @CurrentUser() user: any) {
    try {
      // ✅ AUTHORIZATION: Pass user info for ownership checks
      const result = await this.tasksService.bulkUpdate(updates, user.id, user.role);

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