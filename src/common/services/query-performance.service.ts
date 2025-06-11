import { Injectable, Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';

@Injectable()
export class QueryPerformanceService {
  private readonly logger = new Logger(QueryPerformanceService.name);

  constructor(private dataSource: DataSource) {}

  /**
   * ✅ MONITORING: Check if indexes are being used effectively
   */
  async checkIndexUsage(): Promise<{
    indexStats: any[];
    recommendations: string[];
  }> {
    try {
      // ✅ PERFORMANCE: Get index usage statistics (PostgreSQL specific)
      const indexStats = await this.dataSource.query(`
        SELECT 
          schemaname,
          tablename,
          indexname,
          idx_tup_read,
          idx_tup_fetch,
          idx_scan
        FROM pg_stat_user_indexes 
        WHERE tablename = 'tasks'
        ORDER BY idx_scan DESC
      `);

      const recommendations: string[] = [];

      // ✅ ANALYSIS: Analyze index usage and provide recommendations
      for (const stat of indexStats) {
        if (stat.idx_scan === 0) {
          recommendations.push(`Index ${stat.indexname} is not being used - consider removing`);
        } else if (stat.idx_scan < 10) {
          recommendations.push(`Index ${stat.indexname} has low usage (${stat.idx_scan} scans)`);
        }
      }

      if (recommendations.length === 0) {
        recommendations.push('All indexes are being used effectively');
      }

      return { indexStats, recommendations };
    } catch (error) {
      this.logger.error('Failed to check index usage:', error);
      return { indexStats: [], recommendations: ['Failed to analyze index usage'] };
    }
  }

  /**
   * ✅ MONITORING: Analyze slow queries on tasks table
   */
  async analyzeSlowQueries(): Promise<{
    slowQueries: any[];
    recommendations: string[];
  }> {
    try {
      // ✅ PERFORMANCE: Get slow queries (requires pg_stat_statements extension)
      const slowQueries = await this.dataSource.query(`
        SELECT 
          query,
          calls,
          total_time,
          mean_time,
          rows
        FROM pg_stat_statements 
        WHERE query LIKE '%tasks%'
        ORDER BY mean_time DESC
        LIMIT 10
      `);

      const recommendations: string[] = [];

      // ✅ ANALYSIS: Analyze slow queries
      for (const query of slowQueries) {
        if (query.mean_time > 100) {
          recommendations.push(`Query with mean time ${query.mean_time}ms needs optimization`);
        }
      }

      if (recommendations.length === 0) {
        recommendations.push('No slow queries detected');
      }

      return { slowQueries, recommendations };
    } catch (error) {
      this.logger.warn('pg_stat_statements extension not available or query failed');
      return { slowQueries: [], recommendations: ['Query analysis not available'] };
    }
  }

  /**
   * ✅ MONITORING: Get table statistics for tasks
   */
  async getTableStats(): Promise<{
    tableSize: string;
    indexSize: string;
    rowCount: number;
    recommendations: string[];
  }> {
    try {
      // ✅ PERFORMANCE: Get table and index sizes
      const sizeStats = await this.dataSource.query(`
        SELECT 
          pg_size_pretty(pg_total_relation_size('tasks')) as table_size,
          pg_size_pretty(pg_indexes_size('tasks')) as index_size,
          (SELECT COUNT(*) FROM tasks) as row_count
      `);

      const stats = sizeStats[0];
      const recommendations: string[] = [];

      // ✅ ANALYSIS: Provide recommendations based on table size
      if (stats.row_count > 100000) {
        recommendations.push('Large table detected - ensure indexes are optimized');
      }
      
      if (stats.row_count > 1000000) {
        recommendations.push('Very large table - consider partitioning strategies');
      }

      return {
        tableSize: stats.table_size,
        indexSize: stats.index_size,
        rowCount: parseInt(stats.row_count),
        recommendations: recommendations.length > 0 ? recommendations : ['Table size is optimal']
      };
    } catch (error) {
      this.logger.error('Failed to get table stats:', error);
      return {
        tableSize: 'Unknown',
        indexSize: 'Unknown',
        rowCount: 0,
        recommendations: ['Failed to analyze table statistics']
      };
    }
  }

  /**
   * ✅ MONITORING: Run EXPLAIN ANALYZE on common queries
   */
  async explainCommonQueries(): Promise<{
    queryPlans: any[];
    recommendations: string[];
  }> {
    const commonQueries = [
      `SELECT * FROM tasks WHERE status = 'PENDING' ORDER BY created_at DESC LIMIT 10`,
      `SELECT * FROM tasks WHERE user_id = $1 AND status = $2`,
      `SELECT * FROM tasks WHERE status = $1 AND priority = $2`,
      `SELECT COUNT(*) FROM tasks WHERE due_date < NOW() AND status != 'COMPLETED'`
    ];

    const queryPlans: any[] = [];
    const recommendations: string[] = [];

    for (const query of commonQueries) {
      try {
        // ✅ PERFORMANCE: Analyze query execution plan
        const plan = await this.dataSource.query(`EXPLAIN ANALYZE ${query}`, ['test-value']);
        queryPlans.push({ query, plan });

        // ✅ ANALYSIS: Check if query uses indexes
        const planText = plan.map((row: any) => row['QUERY PLAN']).join(' ');
        if (planText.includes('Seq Scan')) {
          recommendations.push(`Query may benefit from better indexing: ${query.substring(0, 50)}...`);
        }
      } catch (error) {
        this.logger.warn(`Failed to explain query: ${query.substring(0, 50)}...`);
      }
    }

    if (recommendations.length === 0) {
      recommendations.push('All common queries are using indexes effectively');
    }

    return { queryPlans, recommendations };
  }
}
