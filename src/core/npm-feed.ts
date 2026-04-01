import { FeedChange } from '../types';
import { fetchJson } from '../utils/registry';

interface ChangeFeedResponse {
  last_seq: number;
  results: Array<{
    seq: number;
    id: string;
    deleted?: boolean;
    doc?: Record<string, unknown>;
  }>;
}

export class NpmFeedSubscriber {
  private readonly changesUrl: string;

  public constructor(private readonly timeoutMs = 25000) {
    this.changesUrl = 'https://replicate.npmjs.com/_changes';
  }

  public async fetchLatestSequence(): Promise<number> {
    const response = await fetchJson<ChangeFeedResponse>(
      `${this.changesUrl}?descending=true&limit=1`,
      { timeoutMs: 10000 },
    );

    if (typeof response.last_seq === 'number') {
      return response.last_seq;
    }

    if (response.results.length > 0) {
      return response.results[0]?.seq ?? 0;
    }

    return 0;
  }

  public async pollOnce(since: number): Promise<{ lastSeq: number; changes: FeedChange[] }> {
    const url = `${this.changesUrl}?include_docs=true&since=${since}&feed=longpoll&timeout=${this.timeoutMs}&limit=100`;
    const response = await fetchJson<ChangeFeedResponse>(url, {
      timeoutMs: this.timeoutMs + 5000,
    });

    return {
      lastSeq: typeof response.last_seq === 'number' ? response.last_seq : since,
      changes: response.results.map((entry) => ({
        sequence: entry.seq,
        packageName: entry.id,
        deleted: entry.deleted,
        doc: entry.doc,
      })),
    };
  }

  public async watch(
    packageNames: Set<string>,
    onChange: (change: FeedChange) => Promise<void>,
    options: {
      startAt?: number;
      once?: boolean;
    } = {},
  ): Promise<void> {
    let since = typeof options.startAt === 'number' ? options.startAt : await this.fetchLatestSequence();

    while (true) {
      const result = await this.pollOnce(since);
      since = result.lastSeq;

      for (const change of result.changes) {
        if (!packageNames.has(change.packageName)) {
          continue;
        }
        await onChange(change);
      }

      if (options.once) {
        return;
      }
    }
  }
}
