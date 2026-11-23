import fs from 'fs';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface BrowserPoolStats {
  activeInstances: number;
  maxInstances: number;
  availableSlots: number;
  totalRendered: number;
  failedRenders: number;
  averageRenderTimeMs: number;
}

export class BrowserClusterService {
  private static instance: BrowserClusterService;
  private browserExe: string | null = null;
  private maxInstances = 5;
  private activeInstances = 0;
  private totalRendered = 0;
  private failedRenders = 0;
  private totalRenderDuration = 0;
  private renderQueue: Array<{
    url: string;
    timeoutMs: number;
    resolve: (html: string | null) => void;
  }> = [];

  private constructor() {
    this.detectBrowserExecutable();
  }

  public static getInstance(): BrowserClusterService {
    if (!BrowserClusterService.instance) {
      BrowserClusterService.instance = new BrowserClusterService();
    }
    return BrowserClusterService.instance;
  }

  private detectBrowserExecutable() {
    const browserCandidates = [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
      'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
    ];

    for (const candidate of browserCandidates) {
      if (fs.existsSync(candidate)) {
        this.browserExe = candidate;
        break;
      }
    }
  }

  public isAvailable(): boolean {
    return this.browserExe !== null;
  }

  public getBrowserPath(): string | null {
    return this.browserExe;
  }

  /**
   * Render dynamic DOM from a single pooled browser slot
   */
  public async renderPage(url: string, timeoutMs: number = 7000): Promise<string | null> {
    if (!this.browserExe) {
      return null;
    }

    if (this.activeInstances >= this.maxInstances) {
      // Wait in queue for an available slot
      return new Promise<string | null>((resolve) => {
        this.renderQueue.push({ url, timeoutMs, resolve });
      });
    }

    return this.executeRender(url, timeoutMs);
  }

  private async executeRender(url: string, timeoutMs: number): Promise<string | null> {
    this.activeInstances++;
    const startTime = Date.now();

    try {
      const { stdout } = await execFileAsync(
        this.browserExe!,
        [
          '--headless=new',
          '--disable-gpu',
          '--no-sandbox',
          '--disable-dev-shm-usage',
          '--disable-extensions',
          '--disable-software-rasterizer',
          '--dump-dom',
          url,
        ],
        {
          timeout: timeoutMs,
          maxBuffer: 20 * 1024 * 1024,
          windowsHide: true,
        }
      );

      const duration = Date.now() - startTime;
      this.totalRendered++;
      this.totalRenderDuration += duration;
      return stdout || null;
    } catch (err) {
      this.failedRenders++;
      return null;
    } finally {
      this.activeInstances--;
      this.processNextInQueue();
    }
  }

  private processNextInQueue() {
    if (this.renderQueue.length > 0 && this.activeInstances < this.maxInstances) {
      const next = this.renderQueue.shift();
      if (next) {
        this.executeRender(next.url, next.timeoutMs).then(next.resolve);
      }
    }
  }

  public getStats(): BrowserPoolStats {
    const avgTime = this.totalRendered > 0 ? Math.round(this.totalRenderDuration / this.totalRendered) : 0;
    return {
      activeInstances: this.activeInstances,
      maxInstances: this.maxInstances,
      availableSlots: Math.max(0, this.maxInstances - this.activeInstances),
      totalRendered: this.totalRendered,
      failedRenders: this.failedRenders,
      averageRenderTimeMs: avgTime,
    };
  }

  public setMaxInstances(count: number) {
    this.maxInstances = Math.max(1, count);
  }
}
