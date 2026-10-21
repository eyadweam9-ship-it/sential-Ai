import EventEmitter from 'events';

export interface ScanJobData {
  scanId: number;
  taskId: number;
  toolName: string;
}

export type JobHandler = (job: ScanJobData) => Promise<void>;

/**
 * Resilient Asynchronous Scan Queue
 * Supports background processing, concurrency limits, task isolation, and failure recovery.
 */
class ScanQueueManager extends EventEmitter {
  private queue: ScanJobData[] = [];
  private running = 0;
  private maxConcurrency = 3;
  private handler: JobHandler | null = null;
  private activeJobs = new Set<string>();

  registerWorker(handler: JobHandler) {
    this.handler = handler;
  }

  async add(job: ScanJobData): Promise<void> {
    this.queue.push(job);
    this.emit('jobAdded', job);
    this.processNext();
  }

  private async processNext(): Promise<void> {
    if (this.running >= this.maxConcurrency || this.queue.length === 0 || !this.handler) {
      return;
    }

    const job = this.queue.shift();
    if (!job) return;

    const jobKey = `${job.scanId}-${job.toolName}`;
    this.activeJobs.add(jobKey);
    this.running++;

    try {
      await this.handler(job);
    } catch (err) {
      console.error(`[ScanQueue] Error executing job ${jobKey}:`, err);
    } finally {
      this.running--;
      this.activeJobs.delete(jobKey);
      this.emit('jobFinished', job);
      // Process subsequent items
      setImmediate(() => this.processNext());
    }
  }

  getQueueStatus() {
    return {
      pending: this.queue.length,
      active: this.running,
      activeJobKeys: Array.from(this.activeJobs),
    };
  }
}

export const scanQueue = new ScanQueueManager();
