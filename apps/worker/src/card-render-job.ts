// Contract for card.render (T-039, ADR 0028). Shared by the producer (API, T-040) and the worker.
// Free of heavy imports on purpose. The job carries ids only: no token, no holder data.

export const CARD_RENDER_QUEUE = 'card.render';

export interface CardRenderJob {
  institutionId: string;
  credentialId: string;
}

/** Retry with backoff. Re-rendering is idempotent (same storage keys are overwritten). */
export const CARD_RENDER_QUEUE_OPTIONS = {
  // 'short': at most one QUEUED job per singletonKey (one per credential), unlimited active.
  policy: 'short',
  retryLimit: 5,
  retryDelay: 30,
  retryBackoff: true,
  expireInSeconds: 300,
  retentionSeconds: 24 * 3600,
  deleteAfterSeconds: 24 * 3600,
} as const;

/** One pending render per credential; a second enqueue while one is queued is a no-op. */
export const cardRenderSingletonKey = (credentialId: string): string => `card.render:${credentialId}`;

export class InvalidCardRenderJobError extends Error {
  constructor() {
    super('invalid card render job payload');
    this.name = 'InvalidCardRenderJobError';
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseCardRenderJobData(data: unknown): CardRenderJob {
  if (typeof data !== 'object' || data === null) throw new InvalidCardRenderJobError();
  const d = data as Record<string, unknown>;
  if (typeof d.institutionId !== 'string' || !UUID.test(d.institutionId)) throw new InvalidCardRenderJobError();
  if (typeof d.credentialId !== 'string' || !UUID.test(d.credentialId)) throw new InvalidCardRenderJobError();
  return { institutionId: d.institutionId, credentialId: d.credentialId };
}

/** Storage keys of the rendered card. Institution-scoped; the API (T-040) reads the same keys. */
export function cardStorageKeys(institutionId: string, credentialId: string): { png: string; pdf: string } {
  const base = `institutions/${institutionId}/credentials/${credentialId}/card`;
  return { png: `${base}.png`, pdf: `${base}.pdf` };
}

/** Enqueue helper for a pg-boss-like sender (API side). Returns false when a render is already queued. */
export interface CardRenderSender {
  send(name: string, data: object, options: Record<string, unknown>): Promise<string | null>;
}
export async function enqueueCardRender(boss: CardRenderSender, job: CardRenderJob): Promise<boolean> {
  const id = await boss.send(CARD_RENDER_QUEUE, { institutionId: job.institutionId, credentialId: job.credentialId }, {
    singletonKey: cardRenderSingletonKey(job.credentialId),
  });
  return id !== null;
}
