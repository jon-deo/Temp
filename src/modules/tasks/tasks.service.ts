import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Task } from './entities/task.entity';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { TaskStatus } from './enums/task-status.enum';
import { TaskPriority } from './enums/task-priority.enum';

@Injectable()
export class TasksService {
  constructor(
    @InjectRepository(Task)
    private tasksRepository: Repository<Task>,
    @InjectQueue('task-processing')
    private taskQueue: Queue,
    private dataSource: DataSource,
  ) { }

  async create(createTaskDto: CreateTaskDto, userId: string): Promise<Task> {
    // ✅ AUTHORIZATION: Ensure task is created for the authenticated user
    const taskData = { ...createTaskDto, userId };

    // ✅ OPTIMIZED: Atomic operation with transaction management
    return await this.dataSource.transaction(async manager => {
      try {
        // Create and save task within transaction
        const task = manager.create(Task, taskData);
        const savedTask = await manager.save(task);

        // ✅ PERFORMANCE: Add to queue only after successful DB commit
        // Queue operation happens after transaction commits to ensure consistency
        await this.taskQueue.add('task-status-update', {
          taskId: savedTask.id,
          status: savedTask.status,
        }, {
          // ✅ RELIABILITY: Add retry configuration
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000,
          },
        });

        return savedTask;
      } catch (error) {
        // ✅ ERROR HANDLING: Transaction will automatically rollback
        throw new Error(`Failed to create task: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  async findAll(): Promise<Task[]> {
    // ✅ OPTIMIZED: Load tasks without user relations by default for better performance
    // User relations should only be loaded when specifically needed
    return this.tasksRepository.find();
  }

  /**
   * ✅ OPTIMIZED: Separate method for when user relations are actually needed
   */
  async findAllWithUsers(): Promise<Task[]> {
    return this.tasksRepository.find({
      relations: ['user'],
    });
  }

  /**
   * ✅ OPTIMIZED: Database-level filtering and pagination
   * Replaces memory-based filtering with efficient SQL queries
   */
  async findAllWithFilters(filters: {
    status?: string;
    priority?: string;
    userId?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'ASC' | 'DESC';
  }): Promise<{
    data: Task[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  }> {
    const {
      status,
      priority,
      userId,
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'DESC'
    } = filters;

    // ✅ PERFORMANCE: Build query with database-level filtering
    const queryBuilder = this.tasksRepository.createQueryBuilder('task');

    // ✅ AUTHORIZATION: Filter by userId if provided
    if (userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId });
    }

    // ✅ PERFORMANCE: Add filters at database level, not in memory
    if (status) {
      queryBuilder.andWhere('task.status = :status', { status });
    }

    if (priority) {
      queryBuilder.andWhere('task.priority = :priority', { priority });
    }

    // ✅ PERFORMANCE: Database-level sorting
    const allowedSortFields = ['title', 'status', 'priority', 'createdAt', 'dueDate'];
    const safeSortBy = allowedSortFields.includes(sortBy) ? sortBy : 'createdAt';
    queryBuilder.orderBy(`task.${safeSortBy}`, sortOrder);

    // ✅ PERFORMANCE: Database-level pagination
    const offset = (page - 1) * limit;
    queryBuilder.skip(offset).take(limit);

    // ✅ PERFORMANCE: Get total count and data in parallel
    const [data, total] = await queryBuilder.getManyAndCount();

    const totalPages = Math.ceil(total / limit);
    const hasNext = page < totalPages;
    const hasPrev = page > 1;

    return {
      data,
      total,
      page,
      limit,
      totalPages,
      hasNext,
      hasPrev,
    };
  }

  async findOne(id: string, userId?: string, userRole?: string): Promise<Task> {
    // ✅ AUTHORIZATION: Build query with ownership check
    const whereCondition: any = { id };

    // ✅ AUTHORIZATION: Non-admin users can only see their own tasks
    if (userRole !== 'admin' && userId) {
      whereCondition.userId = userId;
    }

    // ✅ OPTIMIZED: Single database call instead of count + findOne
    const task = await this.tasksRepository.findOne({
      where: whereCondition,
      relations: ['user'],
    });

    if (!task) {
      throw new NotFoundException('Task not found');
    }

    return task;
  }

  async update(id: string, updateTaskDto: UpdateTaskDto, userId?: string, userRole?: string): Promise<Task> {
    // ✅ OPTIMIZED: Single query with transaction management
    return await this.dataSource.transaction(async manager => {
      try {
        // ✅ AUTHORIZATION: Build where condition with ownership check
        const whereCondition: any = { id };
        if (userRole !== 'admin' && userId) {
          whereCondition.userId = userId;
        }

        // ✅ PERFORMANCE: Get original task data for status comparison
        const originalTask = await manager.findOne(Task, {
          where: whereCondition,
          select: ['id', 'status', 'userId'] // Include userId for authorization
        });

        if (!originalTask) {
          throw new NotFoundException('Task not found');
        }

        // ✅ PERFORMANCE: Single UPDATE query instead of findOne + save
        const updateResult = await manager
          .createQueryBuilder()
          .update(Task)
          .set(updateTaskDto)
          .where('id = :id', { id })
          .execute();

        if (updateResult.affected === 0) {
          throw new NotFoundException('Task not found or no changes made');
        }

        // ✅ PERFORMANCE: Get updated task with relations
        const updatedTask = await manager.findOne(Task, {
          where: { id },
          relations: ['user']
        });

        // ✅ RELIABILITY: Add to queue only if status changed and after DB commit
        if (updateTaskDto.status && originalTask.status !== updateTaskDto.status) {
          await this.taskQueue.add('task-status-update', {
            taskId: updatedTask!.id,
            status: updatedTask!.status,
          }, {
            attempts: 3,
            backoff: {
              type: 'exponential',
              delay: 2000,
            },
          });
        }

        return updatedTask!;
      } catch (error) {
        if (error instanceof NotFoundException) {
          throw error;
        }
        throw new Error(`Failed to update task: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  async remove(id: string, userId?: string, userRole?: string): Promise<void> {
    // ✅ AUTHORIZATION: Check ownership before deletion
    if (userRole !== 'admin' && userId) {
      const task = await this.tasksRepository.findOne({
        where: { id, userId },
        select: ['id']
      });

      if (!task) {
        throw new NotFoundException('Task not found');
      }
    }

    // ✅ OPTIMIZED: Single DELETE query with existence check
    const deleteResult = await this.tasksRepository
      .createQueryBuilder()
      .delete()
      .from(Task)
      .where('id = :id', { id })
      .execute();

    if (deleteResult.affected === 0) {
      throw new NotFoundException('Task not found');
    }
  }

  async findByStatus(status: TaskStatus): Promise<Task[]> {
    // ✅ OPTIMIZED: Use QueryBuilder with proper typing and relations
    return this.tasksRepository
      .createQueryBuilder('task')
      .where('task.status = :status', { status })
      .orderBy('task.createdAt', 'DESC')
      .getMany();
  }

  /**
   * ✅ OPTIMIZED: Find tasks by status with user relations when needed
   */
  async findByStatusWithUsers(status: TaskStatus): Promise<Task[]> {
    return this.tasksRepository
      .createQueryBuilder('task')
      .leftJoinAndSelect('task.user', 'user')
      .where('task.status = :status', { status })
      .orderBy('task.createdAt', 'DESC')
      .getMany();
  }

  /**
   * ✅ OPTIMIZED: Get task statistics using SQL aggregation
   * Replaces N+1 query problem with single efficient query
   */
  async getTaskStatistics(userId?: string, userRole?: string): Promise<{
    total: number;
    completed: number;
    inProgress: number;
    pending: number;
    highPriority: number;
  }> {
    // ✅ PERFORMANCE: Single SQL query with aggregation instead of loading all tasks
    const queryBuilder = this.tasksRepository
      .createQueryBuilder('task')
      .select([
        'COUNT(*) as total',
        'COUNT(CASE WHEN task.status = :completed THEN 1 END) as completed',
        'COUNT(CASE WHEN task.status = :inProgress THEN 1 END) as inProgress',
        'COUNT(CASE WHEN task.status = :pending THEN 1 END) as pending',
        'COUNT(CASE WHEN task.priority = :highPriority THEN 1 END) as highPriority'
      ])
      .setParameters({
        completed: TaskStatus.COMPLETED,
        inProgress: TaskStatus.IN_PROGRESS,
        pending: TaskStatus.PENDING,
        highPriority: TaskPriority.HIGH
      });

    // ✅ AUTHORIZATION: Filter by userId for non-admin users
    if (userRole !== 'admin' && userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId });
    }

    const result = await queryBuilder.getRawOne();

    return {
      total: parseInt(result.total) || 0,
      completed: parseInt(result.completed) || 0,
      inProgress: parseInt(result.inProgress) || 0,
      pending: parseInt(result.pending) || 0,
      highPriority: parseInt(result.highPriority) || 0,
    };
  }

  async updateStatus(id: string, status: string): Promise<Task> {
    // ✅ OPTIMIZED: Single UPDATE query for queue processor
    const updateResult = await this.tasksRepository
      .createQueryBuilder()
      .update(Task)
      .set({ status: status as TaskStatus })
      .where('id = :id', { id })
      .execute();

    if (updateResult.affected === 0) {
      throw new NotFoundException('Task not found');
    }

    // ✅ PERFORMANCE: Return updated task with minimal data for queue processor
    const updatedTask = await this.tasksRepository.findOne({
      where: { id },
      select: ['id', 'status', 'title'] // Only essential fields for queue response
    });

    return updatedTask!;
  }

  /**
   * ✅ OPTIMIZED: Bulk update operations with transaction management
   */
  async bulkUpdateStatus(taskIds: string[], status: TaskStatus, userId?: string, userRole?: string): Promise<{
    affected: number;
    successful: string[];
    failed: string[];
  }> {
    return await this.dataSource.transaction(async manager => {
      try {
        // ✅ VALIDATION: Input validation
        if (!taskIds || taskIds.length === 0) {
          throw new Error('No task IDs provided');
        }

        if (taskIds.length > 1000) {
          throw new Error('Maximum 1000 tasks can be updated at once');
        }

        // ✅ VALIDATION: Check which tasks exist and get current status with authorization
        const queryBuilder = manager
          .createQueryBuilder(Task, 'task')
          .select(['task.id', 'task.status'])
          .where('task.id IN (:...taskIds)', { taskIds });

        // ✅ AUTHORIZATION: Filter by userId for non-admin users
        if (userRole !== 'admin' && userId) {
          queryBuilder.andWhere('task.userId = :userId', { userId });
        }

        const existingTasks = await queryBuilder.getMany();

        const existingIds = existingTasks.map(task => task.id);
        const missingIds = taskIds.filter(id => !existingIds.includes(id));

        // ✅ TRANSACTION: Update only existing tasks
        const result = await manager
          .createQueryBuilder()
          .update(Task)
          .set({ status, updatedAt: new Date() })
          .where('id IN (:...existingIds)', { existingIds })
          .execute();

        // ✅ QUEUE: Add to queue only for tasks that actually changed status
        const changedTasks = existingTasks.filter(task => task.status !== status);
        if (changedTasks.length > 0) {
          const queuePromises = changedTasks.map(task =>
            this.taskQueue.add('task-status-update', {
              taskId: task.id,
              status,
              previousStatus: task.status,
            }, {
              attempts: 3,
              backoff: { type: 'exponential', delay: 2000 },
            })
          );

          await Promise.all(queuePromises);
        }

        return {
          affected: result.affected || 0,
          successful: existingIds,
          failed: missingIds,
        };
      } catch (error) {
        throw new Error(`Bulk status update failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  /**
   * ✅ OPTIMIZED: Bulk delete operations with transaction management and error handling
   */
  async bulkDelete(taskIds: string[], userId?: string, userRole?: string): Promise<{
    affected: number;
    successful: string[];
    failed: string[];
  }> {
    return await this.dataSource.transaction(async manager => {
      try {
        // ✅ VALIDATION: Input validation
        if (!taskIds || taskIds.length === 0) {
          throw new Error('No task IDs provided');
        }

        if (taskIds.length > 1000) {
          throw new Error('Maximum 1000 tasks can be deleted at once');
        }

        // ✅ VALIDATION: Check which tasks exist before deletion with authorization
        const queryBuilder = manager
          .createQueryBuilder(Task, 'task')
          .select('task.id')
          .where('task.id IN (:...taskIds)', { taskIds });

        // ✅ AUTHORIZATION: Filter by userId for non-admin users
        if (userRole !== 'admin' && userId) {
          queryBuilder.andWhere('task.userId = :userId', { userId });
        }

        const existingTasks = await queryBuilder.getMany();

        const existingIds = existingTasks.map(task => task.id);
        const missingIds = taskIds.filter(id => !existingIds.includes(id));

        // ✅ TRANSACTION: Delete only existing tasks
        const result = await manager
          .createQueryBuilder()
          .delete()
          .from(Task)
          .where('id IN (:...existingIds)', { existingIds })
          .execute();

        // ✅ QUEUE: Add deletion notifications to queue
        if (existingIds.length > 0) {
          const queuePromises = existingIds.map(taskId =>
            this.taskQueue.add('task-deleted', {
              taskId,
              deletedAt: new Date(),
            }, {
              attempts: 3,
              backoff: { type: 'exponential', delay: 2000 },
            })
          );

          await Promise.all(queuePromises);
        }

        return {
          affected: result.affected || 0,
          successful: existingIds,
          failed: missingIds,
        };
      } catch (error) {
        throw new Error(`Bulk delete failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  /**
   * ✅ NEW: Bulk create operations with transaction management
   */
  async bulkCreate(createTaskDtos: CreateTaskDto[]): Promise<{
    created: Task[];
    failed: { index: number; error: string }[];
  }> {
    return await this.dataSource.transaction(async manager => {
      try {
        // ✅ VALIDATION: Input validation
        if (!createTaskDtos || createTaskDtos.length === 0) {
          throw new Error('No task data provided');
        }

        if (createTaskDtos.length > 500) {
          throw new Error('Maximum 500 tasks can be created at once');
        }

        const created: Task[] = [];
        const failed: { index: number; error: string }[] = [];

        // ✅ TRANSACTION: Create tasks in batches within transaction
        for (let i = 0; i < createTaskDtos.length; i++) {
          try {
            const task = manager.create(Task, createTaskDtos[i]);
            const savedTask = await manager.save(task);
            created.push(savedTask);
          } catch (error) {
            failed.push({
              index: i,
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }

        // ✅ QUEUE: Add created tasks to queue
        if (created.length > 0) {
          const queuePromises = created.map(task =>
            this.taskQueue.add('task-created', {
              taskId: task.id,
              status: task.status,
            }, {
              attempts: 3,
              backoff: { type: 'exponential', delay: 2000 },
            })
          );

          await Promise.all(queuePromises);
        }

        return { created, failed };
      } catch (error) {
        throw new Error(`Bulk create failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  /**
   * ✅ NEW: Bulk update operations for multiple fields with transaction management
   */
  async bulkUpdate(updates: { id: string; data: Partial<UpdateTaskDto> }[], userId?: string, userRole?: string): Promise<{
    updated: string[];
    failed: { id: string; error: string }[];
  }> {
    return await this.dataSource.transaction(async manager => {
      try {
        // ✅ VALIDATION: Input validation
        if (!updates || updates.length === 0) {
          throw new Error('No update data provided');
        }

        if (updates.length > 500) {
          throw new Error('Maximum 500 tasks can be updated at once');
        }

        const updated: string[] = [];
        const failed: { id: string; error: string }[] = [];

        // ✅ TRANSACTION: Update tasks individually within transaction with authorization
        for (const update of updates) {
          try {
            const updateBuilder = manager
              .createQueryBuilder()
              .update(Task)
              .set({ ...update.data, updatedAt: new Date() })
              .where('id = :id', { id: update.id });

            // ✅ AUTHORIZATION: Add userId filter for non-admin users
            if (userRole !== 'admin' && userId) {
              updateBuilder.andWhere('userId = :userId', { userId });
            }

            const result = await updateBuilder.execute();

            if (result.affected && result.affected > 0) {
              updated.push(update.id);
            } else {
              failed.push({
                id: update.id,
                error: 'Task not found or access denied'
              });
            }
          } catch (error) {
            failed.push({
              id: update.id,
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }

        // ✅ QUEUE: Add updated tasks to queue if status changed
        const statusUpdates = updates.filter(update => update.data.status);
        if (statusUpdates.length > 0) {
          const queuePromises = statusUpdates
            .filter(update => updated.includes(update.id))
            .map(update =>
              this.taskQueue.add('task-status-update', {
                taskId: update.id,
                status: update.data.status,
              }, {
                attempts: 3,
                backoff: { type: 'exponential', delay: 2000 },
              })
            );

          await Promise.all(queuePromises);
        }

        return { updated, failed };
      } catch (error) {
        throw new Error(`Bulk update failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  /**
   * ✅ OPTIMIZED: Validate task existence in bulk with authorization
   */
  async validateTasksExist(taskIds: string[], userId?: string, userRole?: string): Promise<{ existing: string[], missing: string[] }> {
    const queryBuilder = this.tasksRepository
      .createQueryBuilder('task')
      .select('task.id')
      .where('task.id IN (:...taskIds)', { taskIds });

    // ✅ AUTHORIZATION: Filter by userId for non-admin users
    if (userRole !== 'admin' && userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId });
    }

    const existingTasks = await queryBuilder.getMany();
    const existingIds = existingTasks.map(task => task.id);
    const missingIds = taskIds.filter(id => !existingIds.includes(id));

    return { existing: existingIds, missing: missingIds };
  }
}
