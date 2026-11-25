export const name = '@igaro/api';
export { buildApp, API_PREFIX } from './app.js';
export { loadConfig, ConfigError } from './config.js';
export { Db, isUuid } from './db.js';
export type { Session, TenantSession, PlatformSession } from './db.js';
export { AppError, NotFoundError } from './errors.js';
export { HolderRepository } from './repositories.js';
