import { Column, CreateDateColumn, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { TaskStatus } from '../enums/task-status.enum';
import { TaskPriority } from '../enums/task-priority.enum';

@Entity('tasks')
// ✅ PERFORMANCE: Strategic indexes for frequently queried columns
@Index('idx_tasks_status', ['status'])
@Index('idx_tasks_priority', ['priority'])
@Index('idx_tasks_user_id', ['userId'])
@Index('idx_tasks_created_at', ['createdAt'])
@Index('idx_tasks_due_date', ['dueDate'])
// ✅ PERFORMANCE: Composite indexes for complex queries
@Index('idx_tasks_status_priority', ['status', 'priority'])
@Index('idx_tasks_user_status', ['userId', 'status'])
@Index('idx_tasks_status_created', ['status', 'createdAt'])
export class Task {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({
    type: 'enum',
    enum: TaskStatus,
    default: TaskStatus.PENDING,
  })
  status: TaskStatus;

  @Column({
    type: 'enum',
    enum: TaskPriority,
    default: TaskPriority.MEDIUM,
  })
  priority: TaskPriority;

  @Column({ name: 'due_date', nullable: true })
  dueDate: Date;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => User, (user) => user.tasks)
  @JoinColumn({ name: 'user_id' })
  user: User;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
} 