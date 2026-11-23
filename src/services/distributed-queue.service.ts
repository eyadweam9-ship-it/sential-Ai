import EventEmitter from 'events';

export type JobPriority = 'CRITICAL' | 'NORMAL' | 'BACKGROUND';

export interface ScanJob<T = any> {
  id: string;
  scanId: number;
  host: string;
  taskType: string;
  priority: JobPriority;
  payload: T;
  queuedAt: number;
  retries: number;
  maxRetries: number;
}

export interface QueueMetrics {
  totalQueued: number;
  activeWorkers: number;
  maxWorkers: number;
  processedCount: number;
  failedCount: number;
  hostActiveCounts: Record<string, number>;
}

export class DistributedQueueService extends EventEmitter {
  private static instance: DistributedQueueService;

  private queues: Record<JobPriority, ScanJob[]> = {
    CRITICAL: [],
    NORMAL: [],
    BACKGROUND: [],
  };

  private activeJobs = new Map<string, ScanJob>();
  private hostActiveCounts = new Map<string, number>();
  private maxConcurrency = 10;
  private maxPerHostConcurrency = 3;
  private processedCount = 0;
  private failedCount = 0;

  private isProcessing = false;

  private constructor() {
    super();
  }

  public static getInstance(): DistributedQueueService {
    if (!DistributedQueueService.instance) {
      DistributedQueueService.instance = new DistributedQueueService();
    }
    return DistributedQueueService.instance;
  }

  /**
   * Enqueue a new scan task with priority
   */
  public enqueue<T = any>(
    scanId: number,
    host: string,
    taskType: string,
    payload: T,
    priority: JobPriority = 'NORMAL',
    maxRetries = 2
  ): ScanJob<T> {
    const job: ScanJob<T> = {
      id: `job_${scanId}_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      scanId,
      host: host.toLowerCase(),
      taskType,
      priority,
      payload,
      queuedAt: Date.now(),
      retries: 0,
      maxRetries,
    };

    this.queues[priority].push(job);
    this.emit('jobEnqueued', job);
    this.triggerProcessing();
    return job;
  }

  /**
   * Process next eligible job respecting global and per-host concurrency
   */
  private async triggerProcessing() {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      while (this.activeJobs.size < this.maxConcurrency) {
        const nextJob = this.getNextEligibleJob();
        if (!nextJob) break;

        this.executeJob(nextJob);
      }
    } finally {
      this.isProcessing = false;
    }
  }

  private getNextEligibleJob(): ScanJob | null {
    const priorities: JobPriority[] = ['CRITICAL', 'NORMAL', 'BACKGROUND'];

    for (const prio of priorities) {
      const queue = this.queues[prio];
      for (let i = 0; i < queue.length; i++) {
        const job = queue[i];
        const currentHostActive = this.hostActiveCounts.get(job.host) || 0;

        if (currentHostActive < this.maxPerHostConcurrency) {
          queue.splice(i, 1);
          return job;
        }
      }
    }

    return null;
  }

  private async executeJob(job: ScanJob) {
    this.activeJobs.set(job.id, job);
    const hostCount = (this.hostActiveCounts.get(job.host) || 0) + 1;
    this.hostActiveCounts.set(job.host, hostCount);

    this.emit('jobStarted', job);

    try {
      // Handled by worker listener
      this.emit('execute', job, async (err?: Error, result?: any) => {
        this.activeJobs.delete(job.id);
        const curCount = Math.max(0, (this.hostActiveCounts.get(job.host) || 1) - 1);
        this.hostActiveCounts.set(job.host, curCount);

        if (err) {
          if (job.retries < job.maxRetries) {
            job.retries++;
            this.queues[job.priority].push(job);
            this.emit('jobRetried', job, err);
          } else {
            this.failedCount++;
            this.emit('jobFailed', job, err);
          }
        } else {
          this.processedCount++;
          this.emit('jobCompleted', job, result);
        }

        this.triggerProcessing();
      });
    } catch (err: any) {
      this.activeJobs.delete(job.id);
      const curCount = Math.max(0, (this.hostActiveCounts.get(job.host) || 1) - 1);
      this.hostActiveCounts.set(job.host, curCount);
      this.failedCount++;
      this.emit('jobFailed', job, err);
      this.triggerProcessing();
    }
  }

  public getMetrics(): QueueMetrics {
    const totalQueued =
      this.queues.CRITICAL.length +
      this.queues.NORMAL.length +
      this.queues.BACKGROUND.length;

    const hostActiveCounts: Record<string, number> = {};
    for (const [h, count] of this.hostActiveCounts.entries()) {
      if (count > 0) hostActiveCounts[h] = count;
    }

    return {
      totalQueued,
      activeWorkers: this.activeJobs.size,
      maxWorkers: this.maxConcurrency,
      processedCount: this.processedCount,
      failedCount: this.failedCount,
      hostActiveCounts,
    };
  }

  public configure(maxWorkers: number, maxPerHost: number) {
    this.maxConcurrency = maxWorkers;
    this.maxPerHostConcurrency = maxPerHost;
  }
}
