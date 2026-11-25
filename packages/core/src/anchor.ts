/** Phase 1 blockchain hook. Nothing in the MVP depends on a chain: the default is NoopAnchorService. */
export type AnchorStatus = 'NOT_ANCHORED' | 'PENDING' | 'ANCHORED' | 'FAILED';

export interface AnchorRequest { credentialId: string; dataHash: string; eventId: string }
export interface AnchorResult { status: AnchorStatus; proof?: unknown }

export interface AnchorService {
  readonly name: string;
  anchor(req: AnchorRequest): Promise<AnchorResult>;
  getStatus(credentialId: string): Promise<AnchorResult>;
}

export class NoopAnchorService implements AnchorService {
  readonly name = 'noop';
  anchor(): Promise<AnchorResult> { return Promise.resolve({ status: 'NOT_ANCHORED' }); }
  getStatus(): Promise<AnchorResult> { return Promise.resolve({ status: 'NOT_ANCHORED' }); }
}
