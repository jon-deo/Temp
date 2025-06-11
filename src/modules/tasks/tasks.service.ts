import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
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
  ) { }

  async create(createTaskDto: CreateTaskDto): Promise<Task> {
    // Inefficient implementation: creates the task but doesn't use a single transaction
    // for creating and adding to queue, potential for inconsistent state
    const task = this.tasksRepository.create(createTaskDto);
    const savedTask = await this.tasksRepository.save(task);

    // Add to queue without waiting for confirmation or handling errors
    this.taskQueue.add('task-status-update', {
      taskId: savedTask.id,
      status: savedTask.status,
    });

    return savedTask;
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
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'DESC'
    } = filters;

    // ✅ PERFORMANCE: Build query with database-level filtering
    const queryBuilder = this.tasksRepository.createQueryBuilder('task');

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

  async findOne(id: string): Promise<Task> {
    // ✅ OPTIMIZED: Single database call instead of count + findOne
    const task = await this.tasksRepository.findOne({
      where: { id },
      relations: ['user'],
    });

    if (!task) {
      throw new NotFoundException('Task not found');
    }

    return task;
  }

  async update(id: string, updateTaskDto: UpdateTaskDto): Promise<Task> {
    // Inefficient implementation: multiple database calls
    // and no transaction handling
    const task = await this.findOne(id);

    const originalStatus = task.status;

    // Directly update each field individually
    if (updateTaskDto.title) task.title = updateTaskDto.title;
    if (updateTaskDto.description) task.description = updateTaskDto.description;
    if (updateTaskDto.status) task.status = updateTaskDto.status;
    if (updateTaskDto.priority) task.priority = updateTaskDto.priority;
    if (updateTaskDto.dueDate) task.dueDate = updateTaskDto.dueDate;

    const updatedTask = await this.tasksRepository.save(task);

    // Add to queue if status changed, but without proper error handling
    if (originalStatus !== updatedTask.status) {
      this.taskQueue.add('task-status-update', {
        taskId: updatedTask.id,
        status: updatedTask.status,
      });
    }

    return updatedTask;
  }

  async remove(id: string): Promise<void> {
    // Inefficient implementation: two separate database calls
    const task = await this.findOne(id);
    await this.tasksRepository.remove(task);
  }

  async findByStatus(status: TaskStatus): Promise<Task[]> {
    // Inefficient implementation: doesn't use proper repository patterns
    const query = 'SELECT * FROM tasks WHERE status = $1';
    return this.tasksRepository.query(query, [status]);
  }

  /**
   * ✅ OPTIMIZED: Get task statistics using SQL aggregation
   * Replaces N+1 query problem with single efficient query
   */
  async getTaskStatistics(): Promise<{
    total: number;
    completed: number;
    inProgress: number;
    pending: number;
    highPriority: number;
  }> {
    // ✅ PERFORMANCE: Single SQL query with aggregation instead of loading all tasks
    const result = await this.tasksRepository
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
      })
      .getRawOne();

    return {
      total: parseInt(result.total) || 0,
      completed: parseInt(result.completed) || 0,
      inProgress: parseInt(result.inProgress) || 0,
      pending: parseInt(result.pending) || 0,
      highPriority: parseInt(result.highPriority) || 0,
    };
  }

  async updateStatus(id: string, status: string): Promise<Task> {
    // This method will be called by the task processor
    const task = await this.findOne(id);
    task.status = status as any;
    return this.tasksRepository.save(task);
  }

  /**
   * ✅ OPTIMIZED: Bulk update operations to replace N+1 queries
   */
  async bulkUpdateStatus(taskIds: string[], status: TaskStatus): Promise<{ affected: number }> {
    // ✅ PERFORMANCE: Single query to update multiple tasks
    const result = await this.tasksRepository
      .createQueryBuilder()
      .update(Task)
      .set({ status })
      .where('id IN (:...taskIds)', { taskIds })
      .execute();

    return { affected: result.affected || 0 };
  }

  /**
   * ✅ OPTIMIZED: Bulk delete operations to replace N+1 queries
   */
  async bulkDelete(taskIds: string[]): Promise<{ affected: number }> {
    // ✅ PERFORMANCE: Single query to delete multiple tasks
    const result = await this.tasksRepository
      .createQueryBuilder()
      .delete()
      .from(Task)
      .where('id IN (:...taskIds)', { taskIds })
      .execute();

    return { affected: result.affected || 0 };
  }

  /**
   * ✅ OPTIMIZED: Validate task existence in bulk
   */
  async validateTasksExist(taskIds: string[]): Promise<{ existing: string[], missing: string[] }> {
    const existingTasks = await this.tasksRepository
      .createQueryBuilder('task')
      .select('task.id')
      .where('task.id IN (:...taskIds)', { taskIds })
      .getMany();

    const existingIds = existingTasks.map(task => task.id);
    const missingIds = taskIds.filter(id => !existingIds.includes(id));

    return { existing: existingIds, missing: missingIds };
  }
}
