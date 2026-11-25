/** Credential lifecycle rules (CLAUDE.md invariant 4). Pure functions; the DB trigger is the backstop. */
export type CredentialStatus = 'DRAFT' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'SUPERSEDED';
export type LifecycleAction = 'ISSUE' | 'SUSPEND' | 'REINSTATE' | 'REVOKE' | 'REISSUE';
export type CredentialEventType = 'ISSUED' | 'SUSPENDED' | 'REINSTATED' | 'REVOKED' | 'REISSUED';

const TRANSITIONS: Record<LifecycleAction, { from: CredentialStatus; to: CredentialStatus; event: CredentialEventType; reason: boolean }[]> = {
  ISSUE: [{ from: 'DRAFT', to: 'ACTIVE', event: 'ISSUED', reason: false }],
  SUSPEND: [{ from: 'ACTIVE', to: 'SUSPENDED', event: 'SUSPENDED', reason: true }],
  REINSTATE: [{ from: 'SUSPENDED', to: 'ACTIVE', event: 'REINSTATED', reason: false }],
  REVOKE: [{ from: 'ACTIVE', to: 'REVOKED', event: 'REVOKED', reason: true }],
  REISSUE: [{ from: 'ACTIVE', to: 'SUPERSEDED', event: 'REISSUED', reason: false }],
};

export const TERMINAL_STATUSES: readonly CredentialStatus[] = ['REVOKED', 'SUPERSEDED'];

export class LifecycleError extends Error {
  constructor(public readonly code: 'INVALID_TRANSITION' | 'REASON_REQUIRED', message: string) {
    super(message);
    this.name = 'LifecycleError';
  }
}

export interface Transition { to: CredentialStatus; event: CredentialEventType }

/** Validates an action against the current status; returns the target status and event type or throws. */
export function planTransition(from: CredentialStatus, action: LifecycleAction, reason?: string): Transition {
  const rule = Object.hasOwn(TRANSITIONS, action) ? TRANSITIONS[action].find((t) => t.from === from) : undefined;
  if (!rule) throw new LifecycleError('INVALID_TRANSITION', `cannot ${String(action)} a credential that is ${String(from)}`);
  if (rule.reason && (typeof reason !== 'string' || reason.trim() === '')) {
    throw new LifecycleError('REASON_REQUIRED', `${action} requires a reason`);
  }
  return { to: rule.to, event: rule.event };
}

export function canTransition(from: CredentialStatus, action: LifecycleAction): boolean {
  return Object.hasOwn(TRANSITIONS, action) && TRANSITIONS[action].some((t) => t.from === from);
}

/** EXPIRED is computed at read time from the signed expiresAt; it is never stored. */
export function isExpired(expiresAt: string | null | undefined, now: Date = new Date()): boolean {
  if (expiresAt == null) return false;
  // Fail closed: anything that is not strict ISO-8601 UTC is treated as expired, never as valid.
  if (typeof expiresAt !== 'string' || !/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?Z)?$/.test(expiresAt)) return true;
  const t = Date.parse(expiresAt);
  return !Number.isFinite(t) || t <= now.getTime();
}
