import { randomUUID } from 'crypto';
import ms from 'ms';

export function createRefreshTokenPlain(): string {
  // token opaque
  return randomUUID() + '.' + randomUUID();
}

export function parseTTL(ttl: string | number): number {
  // retourne secondes
  if (typeof ttl === 'number') return ttl;
  try {
    return Math.floor(ms(ttl) / 1000);
  } catch {
    // fallback
    return 60 * 15;
  }
}
