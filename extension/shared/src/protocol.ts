/**
 * Protocol types shared between the extension and the native host.
 * Mirrors protocol/schema/*.schema.json — keep in sync.
 */

export const PROTOCOL_VERSION = 1;
export const EVENT_SCHEMA_VERSION = 1;

/** Event types, mirroring event.schema.json. */
export type EventType =
  | 'connection'
  | 'dns'
  | 'navigation'
  | 'process'
  | 'status'
  | 'error';

/** Observation source. */
export type EventSource = 'ebpf' | 'pcap' | 'browser';

/** Daemon operations available to the extension. */
export type Operation =
  | 'hello'
  | 'get_status'
  | 'subscribe'
  | 'unsubscribe'
  | 'set_policy'
  | 'get_policy';

/** Stable error codes. */
export type ErrorCode =
  | 'invalid_framing'
  | 'message_too_large'
  | 'invalid_json'
  | 'schema_violation'
  | 'unsupported_version'
  | 'unknown_operation'
  | 'operation_not_allowed'
  | 'too_many_subscriptions'
  | 'queue_overflow'
  | 'client_timeout'
  | 'daemon_unavailable'
  | 'socket_permission'
  | 'connection_closed'
  | 'backend_unavailable'
  | 'missing_permission'
  | 'capture_filter_error'
  | 'backend_load_failure'
  | 'storage_error'
  | 'policy_violation'
  | 'internal_error';

/** Process metadata attached to events. */
export interface ProcessInfo {
  pid: number;
  name: string;
  uid?: number;
}

/** Network metadata. Addresses are textual; nothing else is captured. */
export interface NetworkInfo {
  transport: 'tcp' | 'udp' | 'icmp' | 'other';
  direction: 'inbound' | 'outbound' | 'unknown';
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  dns_query_name?: string;
  dns_response_code?: number;
  interface?: string;
  backend: EventSource;
}

/** Browser correlation data — present only when evidence exists. */
export interface BrowserInfo {
  tab_id: number;
  window_id: number;
  url: string;
  title?: string;
  navigation_id?: string;
  frame_id?: number;
}

/** Redaction annotations. */
export type RedactionKind =
  | 'query_string'
  | 'fragment'
  | 'hostname_hash'
  | 'hostname_mask'
  | 'domain_excluded';

export interface PrivacyInfo {
  redacted: boolean;
  metadata_only: true;
  redactions: RedactionKind[];
}

/** Normalized event, mirroring event.schema.json. */
export interface EzcapEvent {
  schema_version: typeof EVENT_SCHEMA_VERSION;
  event_id: string;
  event_type: EventType;
  timestamp: string;
  source: EventSource;
  confidence: number;
  process?: ProcessInfo;
  network?: NetworkInfo;
  browser?: BrowserInfo;
  privacy: PrivacyInfo;
  error?: { code: string; message: string; component?: string };
  status?: {
    state: string;
    backends: Array<{ name: string; active: boolean; detail?: string }>;
  };
}

/** Envelope kinds on the native messaging channel. */
export type NativeMessage =
  | { kind: 'request'; payload: NativeRequest }
  | { kind: 'response'; payload: NativeResponse }
  | { kind: 'event'; payload: EzcapEvent }
  | { kind: 'error'; payload: NativeError };

/** A request to forward to the daemon. */
export interface NativeRequest {
  operation: Operation;
  request_id: string;
  params?: Record<string, unknown>;
}

/** Daemon response as relayed by the host. */
export interface NativeResponse {
  request_id: string;
  ok: boolean;
  result?: Record<string, unknown>;
}

/** Structured error as relayed by the host. */
export interface NativeError {
  request_id?: string | null;
  code: ErrorCode;
  message: string;
}

/** Attribution confidence bands (presentation only). */
export function confidenceBand(confidence: number): string {
  if (confidence >= 0.9) return 'direct';
  if (confidence >= 0.7) return 'strong';
  if (confidence >= 0.4) return 'probable';
  return 'weak';
}

/** Human labels for transport names. */
export const transportLabels: Record<string, string> = {
  tcp: 'TCP',
  udp: 'UDP',
  icmp: 'ICMP',
  other: 'other',
};
