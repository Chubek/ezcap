/**
 * Event model utilities: validation, filtering, and presentation helpers.
 * All events are metadata-only by construction; this module additionally
 * rejects any event that carries forbidden fields, defensively.
 */

import type { EzcapEvent, EventType } from './protocol';
import { EVENT_SCHEMA_VERSION } from './protocol';

/** Fields that must never appear on an event. */
const FORBIDDEN_FIELDS = [
  'payload',
  'body',
  'cookies',
  'authorization',
  'password',
  'api_key',
] as const;

/**
 * Structural validation of a decoded event. Returns null (and logs the
 * reason) when the event is malformed or carries forbidden fields; a
 * returning event is safe to display and store.
 */
export function validateEvent(candidate: unknown): EzcapEvent | null {
  if (typeof candidate !== 'object' || candidate === null) {
    return null;
  }
  const event = candidate as Record<string, unknown>;

  for (const field of FORBIDDEN_FIELDS) {
    if (field in event) {
      console.warn(`ezcap: rejected event containing forbidden field '${field}'`);
      return null;
    }
  }

  if (event.schema_version !== EVENT_SCHEMA_VERSION) {
    return null;
  }
  if (typeof event.event_id !== 'string' || event.event_id.length === 0) {
    return null;
  }
  if (typeof event.event_type !== 'string') {
    return null;
  }
  if (typeof event.timestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(event.timestamp)) {
    return null;
  }
  if (typeof event.confidence !== 'number' || event.confidence < 0 || event.confidence > 1) {
    return null;
  }
  if (event.privacy === undefined || (event.privacy as Record<string, unknown>).metadata_only !== true) {
    return null;
  }

  return candidate as EzcapEvent;
}

/** Filter events by type list; empty list = all types. */
export function filterByTypes(
  events: EzcapEvent[],
  types: EventType[],
): EzcapEvent[] {
  if (types.length === 0) {
    return events;
  }
  const wanted = new Set<string>(types);
  return events.filter((event) => wanted.has(event.event_type));
}

/**
 * Sort events newest-first (in place).
 */
export function sortNewestFirst(events: EzcapEvent[]): EzcapEvent[] {
  return events.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

/**
 * A short, non-sensitive summary of an event for list views: type,
 * remote endpoint or host, and the confidence band.
 */
export function summarizeEvent(event: EzcapEvent): string {
  switch (event.event_type) {
    case 'dns':
      return event.network?.dns_query_name
        ? `dns ${event.network.dns_query_name}`
        : 'dns';
    case 'connection': {
      const net = event.network;
      if (!net) return 'connection';
      const host = net.remote_address || 'unknown host';
      const port = net.remote_port ? `:${net.remote_port}` : '';
      return `${net.transport} ${host}${port}`;
    }
    case 'navigation':
      return event.browser ? `tab ${event.browser.tab_id}` : 'navigation';
    case 'status':
      return event.status ? `daemon ${event.status.state}` : 'status';
    case 'error':
      return event.error ? `error ${event.error.code}` : 'error';
    default:
      return event.event_type;
  }
}
