/**
 * Native Messaging port management.
 *
 * The browser side of the bridge: connects to the native host, sends
 * allowlisted requests, and receives responses, events, and errors. The
 * extension never sees raw sockets — all daemon traffic flows through
 * this port, and the host enforces the operation allowlist on its side.
 */

import type {
  EzcapEvent,
  NativeMessage,
  NativeRequest,
  NativeResponse,
  NativeError,
  Operation,
} from './protocol';
import { PROTOCOL_VERSION } from './protocol';

/** Native host name; must match the manifests. */
export const NATIVE_HOST_NAME = 'com.ezcap.host';

type Port = {
  postMessage(message: unknown): void;
  onMessage: {
    addListener(listener: (message: unknown) => void): void;
    removeListener(listener: (message: unknown) => void): void;
  };
  onDisconnect: {
    addListener(listener: () => void): void;
    removeListener(listener: () => void): void;
  };
  disconnect(): void;
};

type BrowserWithNative = {
  runtime: {
    connectNative(name: string): Port;
    sendNativeMessage?(name: string, message: unknown): Promise<unknown>;
    lastError?: { message?: string };
  };
};

function getBrowser(): BrowserWithNative | null {
  const globalScope = globalThis as Record<string, unknown>;
  const candidates: unknown[] = [globalScope['browser'], globalScope['chrome']];
  for (const candidate of candidates) {
    if (
      typeof candidate === 'object' &&
      candidate !== null &&
      typeof (candidate as BrowserWithNative).runtime?.connectNative === 'function'
    ) {
      return candidate as BrowserWithNative;
    }
  }
  return null;
}

export interface NativeMessagingOptions {
  /** Called for each decoded event. */
  onEvent: (event: EzcapEvent) => void;
  /** Called for each response (matched by request id). */
  onResponse?: (response: NativeResponse) => void;
  /** Called for each error envelope. */
  onError?: (error: NativeError) => void;
  /** Called when the host disconnects. */
  onDisconnect?: (reason: string) => void;
  /** Called after a successful (re)connect. */
  onConnect?: () => void;
}

export class NativeMessaging {
  private port: Port | null = null;
  private connected = false;
  private listeners = new Set<(message: NativeMessage) => void>();
  private options: NativeMessagingOptions;

  constructor(options: NativeMessagingOptions) {
    this.options = options;
  }

  /** Whether the port is currently connected. */
  isConnected(): boolean {
    return this.connected;
  }

  /** Connect (or reconnect) to the native host. */
  connect(): boolean {
    const b = getBrowser();
    if (!b) {
      this.options.onDisconnect?.('native messaging unavailable');
      return false;
    }
    if (this.connected) {
      return true;
    }

    try {
      this.port = b.runtime.connectNative(NATIVE_HOST_NAME);
    } catch (err) {
      this.options.onDisconnect?.(err instanceof Error ? err.message : 'connect failed');
      return false;
    }

    this.port.onMessage.addListener(this.handleMessage);
    this.port.onDisconnect.addListener(this.handleDisconnect);
    this.connected = true;
    this.options.onConnect?.();
    return true;
  }

  /** Disconnect from the host. */
  disconnect(): void {
    if (this.port) {
      this.port.onMessage.removeListener(this.handleMessage);
      this.port.onDisconnect.removeListener(this.handleDisconnect);
      this.port.disconnect();
      this.port = null;
    }
    this.connected = false;
  }

  /** Subscribe to all decoded messages (used by tests and the options page). */
  addListener(listener: (message: NativeMessage) => void): void {
    this.listeners.add(listener);
  }

  removeListener(listener: (message: NativeMessage) => void): void {
    this.listeners.delete(listener);
  }

  /**
   * Send a request to the daemon through the host. Returns the request id,
   * or null when not connected. Responses arrive via onResponse.
   */
  sendRequest(
    operation: Operation,
    params?: Record<string, unknown>,
    requestId?: string,
  ): string | null {
    if (!this.port || !this.connected) {
      return null;
    }
    const request: NativeRequest = {
      operation,
      request_id: requestId ?? newRequestId(),
      ...(params !== undefined ? { params } : {}),
    };
    this.port.postMessage({ protocol_version: PROTOCOL_VERSION, kind: 'request', payload: request });
    return request.request_id;
  }

  private handleMessage = (raw: unknown): void => {
    const message = decodeMessage(raw);
    if (!message) {
      return; // malformed: ignored; the host logs and counts these
    }
    for (const listener of this.listeners) {
      listener(message);
    }
    switch (message.kind) {
      case 'event':
        this.options.onEvent(message.payload);
        break;
      case 'response':
        this.options.onResponse?.(message.payload);
        break;
      case 'error':
        this.options.onError?.(message.payload);
        break;
      default:
        break;
    }
  };

  private handleDisconnect = (): void => {
    this.connected = false;
    this.port = null;
    const b = getBrowser();
    const reason = b?.runtime.lastError?.message ?? 'native host disconnected';
    this.options.onDisconnect?.(reason);
  };}

/** Decode and structurally check a raw port message. */
export function decodeMessage(raw: unknown): NativeMessage | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const message = raw as Record<string, unknown>;
  if (message.protocol_version !== PROTOCOL_VERSION) {
    return null;
  }
  if (typeof message.kind !== 'string' || typeof message.payload !== 'object') {
    return null;
  }
  switch (message.kind) {
    case 'request':
      return null; // requests never flow host -> extension
    case 'response':
    case 'event':
    case 'error':
      return raw as NativeMessage;
    default:
      return null;
  }
}

let requestCounter = 0;

function newRequestId(): string {
  requestCounter += 1;
  return `ext-${Date.now().toString(36)}-${requestCounter}`;
}
