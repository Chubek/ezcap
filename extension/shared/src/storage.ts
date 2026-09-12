/**
 * Bounded in-browser event storage.
 *
 * The extension keeps only a small, bounded ring of recent events for the
 * popup and options views. Events are metadata-only (enforced by
 * validateEvent before insertion) and are evicted oldest-first. Clearing
 * is explicit and total.
 */

import type { EzcapEvent } from './protocol';

const STORAGE_KEY = 'ezcap.events';
const MAX_EVENTS = 5000;

type StorageArea = {
  get(keys: string[] | string | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string[] | string | null): Promise<void>;
};

function getStorage(): StorageArea | null {
  const b = (globalThis as Record<string, unknown>).browser ?? undefined;
  if (b && (b as { storage?: { local?: StorageArea } }).storage?.local) {
    return (b as { storage: { local: StorageArea } }).storage.local;
  }
  const c = (globalThis as Record<string, unknown>).chrome ?? undefined;
  if (c && (c as { storage?: { local?: StorageArea } }).storage?.local) {
    return (c as { storage: { local: StorageArea } }).storage.local;
  }
  return null;
}

/** Append events, evicting oldest-first beyond the cap. Resolves when persisted. */
export async function appendEvents(events: EzcapEvent[]): Promise<void> {
  if (events.length === 0) {
    return;
  }
  const storage = getStorage();
  if (!storage) {
    return;
  }
  const existing = await loadEvents();
  const combined = existing.concat(events);
  const overflow = Math.max(0, combined.length - MAX_EVENTS);
  const bounded = overflow > 0 ? combined.slice(overflow) : combined;
  await storage.set({ [STORAGE_KEY]: bounded });
}

/** Load all stored events (oldest-first). */
export async function loadEvents(): Promise<EzcapEvent[]> {
  const storage = getStorage();
  if (!storage) {
    return [];
  }
  const items = await storage.get(STORAGE_KEY);
  const value = items[STORAGE_KEY];
  return Array.isArray(value) ? (value as EzcapEvent[]) : [];
}

/** Delete every stored event. */
export async function clearEvents(): Promise<void> {
  const storage = getStorage();
  if (!storage) {
    return;
  }
  await storage.remove(STORAGE_KEY);
}

/** Number of stored events (bounded by the cap). */
export async function eventCount(): Promise<number> {
  return (await loadEvents()).length;
}

/** Simple preference accessors (booleans/strings only). */
export async function getPreference<T>(key: string, fallback: T): Promise<T> {
  const storage = getStorage();
  if (!storage) {
    return fallback;
  }
  const items = await storage.get(key);
  return key in items ? (items[key] as T) : fallback;
}

export async function setPreference(key: string, value: unknown): Promise<void> {
  const storage = getStorage();
  if (!storage) {
    return;
  }
  await storage.set({ [key]: value });
}
