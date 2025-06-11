import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddTaskIndexes1703000000000 implements MigrationInterface {
  name = 'AddTaskIndexes1703000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // ✅ PERFORMANCE: Add single column indexes for frequently queried fields
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_status" ON "tasks" ("status")
    `);
    
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_priority" ON "tasks" ("priority")
    `);
    
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_user_id" ON "tasks" ("user_id")
    `);
    
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_created_at" ON "tasks" ("created_at")
    `);
    
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_due_date" ON "tasks" ("due_date")
    `);

    // ✅ PERFORMANCE: Add composite indexes for complex queries
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_status_priority" ON "tasks" ("status", "priority")
    `);
    
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_user_status" ON "tasks" ("user_id", "status")
    `);
    
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_status_created" ON "tasks" ("status", "created_at")
    `);

    // ✅ PERFORMANCE: Add partial index for overdue tasks (PostgreSQL specific)
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "idx_tasks_overdue" ON "tasks" ("due_date") 
      WHERE "status" != 'COMPLETED' AND "due_date" < NOW()
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // ✅ ROLLBACK: Remove all indexes in reverse order
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_overdue"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_status_created"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_user_status"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_status_priority"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_due_date"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_created_at"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_user_id"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_priority"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_tasks_status"`);
  }
}
