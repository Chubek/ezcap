/**
 * Background service worker: the extension's brain.
 *
 * - maintains the native messaging connection (with reconnect),
 * - subscribes to daemon events and stores the bounded local ring,
 * - reports navigation observations to the daemon for correlation,
 * - exposes a message router for the popup and options pages.
 */

import { NativeMessaging } from '../../shared/src/native-messaging';
import { validateEvent } from '../../shared/src/event-model';
import {
  appendEvents,
  clearEvents,
  loadEvents,
  getPreference,
} from '../../shared/src/storage';
import type { EzcapEvent } from '../../shared/src/protocol';

const RECONNECT_DELAY_MS = 5000;

type RuntimeMessage =
  | { type: 'ezcap:getEvents'; limit?: number }
  | { type: 'ezcap:getStatus' }
  | { type: 'ezcap:clear' }
  | { type: 'ezcap:connect' };

const messaging = new NativeMessaging({
  onEvent: (event) => {
    const valid = validateEvent(event);
    if (valid) {
      void appendEvents([valid]);
    }
  },
  onDisconnect: () => {
    scheduleReconnect();
  },
});

let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let connectedOnce = false;

function scheduleReconnect(): void {
  if (reconnectTimer !== null) {
    return;
  }
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectAndSubscribe();
  }, RECONNECT_DELAY_MS);
}

function connectAndSubscribe(): void {
  if (!messaging.connect()) {
    scheduleReconnect();
    return;
  }
  connectedOnce = true;
  messaging.sendRequest('hello');
  messaging.sendRequest('subscribe');
}

// --- Navigation observations (correlation evidence) ---------------------
// The daemon uses these, combined with eBPF process data, to attribute
// network events to tabs. Only already-redacted metadata is sent; the
// URL is passed as-is because the daemon applies its own redaction
// policy before any further use.

type TabsApi = {
  query(query: Record<string, unknown>): Promise<
    Array<{ id?: number; windowId?: number; url?: string; title?: string }>
  >;
  onUpdated: {
    addListener(
      listener: (
        tabId: number,
        change: { status?: string; url?: string; title?: string },
        tab: { windowId?: number; url?: string; title?: string },
      ) => void,
    ): void;
  };
};

function getTabs(): TabsApi | null {
  const b = (globalThis as Record<string, unknown>).browser ?? undefined;
  if (b && (b as { tabs?: TabsApi }).tabs) {
    return (b as { tabs: TabsApi }).tabs;
  }
  const c = (globalThis as Record<string, unknown>).chrome ?? undefined;
  if (c && (c as { tabs?: TabsApi }).tabs) {
    return (c as { tabs: TabsApi }).tabs;
  }
  return null;
}

function reportNavigation(
  tabId: number,
  windowId: number,
  url: string | undefined,
  title: string | undefined,
): void {
  if (!url || !/^https?:/i.test(url)) {
    return; // scheme allowlist: no file:, chrome:, about:, etc.
  }
  messaging.sendRequest('subscribe', {
    observation: {
      kind: 'navigation',
      tab_id: tabId,
      window_id: windowId,
      url,
      title: title ?? '',
      timestamp: new Date().toISOString(),
    },
  });
}

const tabs = getTabs();
if (tabs) {
  tabs.onUpdated.addListener((tabId, change, tab) => {
    if (change.status === 'complete' || change.url !== undefined) {
      reportNavigation(tabId, tab.windowId ?? 0, tab.url ?? change.url, tab.title);
    }
  });
}

// --- Message router for popup/options ------------------------------------

type MessageSender = (message: unknown) => Promise<unknown> | void;

function installRouter(): void {
  const b = (globalThis as Record<string, unknown>).browser ?? undefined;
  const c = (globalThis as Record<string, unknown>).chrome ?? undefined;
  const runtime =
    (b as { runtime?: { onMessage?: { addListener(listener: MessageSender): void } } })?.runtime ??
    (c as { runtime?: { onMessage?: { addListener(listener: MessageSender): void } } })?.runtime;
  if (!runtime?.onMessage) {
    return;
  }
  runtime.onMessage.addListener((raw: unknown) => {
    void handleRoute(raw);
  });
}

async function handleRoute(raw: unknown): Promise<unknown> {
  if (typeof raw !== 'object' || raw === null) {
    return { ok: false, error: 'bad request' };
  }
  const message = raw as RuntimeMessage;
  switch (message.type) {
    case 'ezcap:getEvents': {
      const all = await loadEvents();
      const limit = Math.min(Math.max(message.limit ?? 100, 1), 1000);
      return { ok: true, events: all.slice(-limit).reverse() as EzcapEvent[] };
    }
    case 'ezcap:getStatus': {
      return {
        ok: true,
        connected: messaging.isConnected(),
        everConnected: connectedOnce,
      };
    }
    case 'ezcap:clear': {
      await clearEvents();
      return { ok: true };
    }
    case 'ezcap:connect': {
      connectAndSubscribe();
      return { ok: true, connected: messaging.isConnected() };
    }
    default:
      return { ok: false, error: 'unknown message' };
  }
}

// --- Startup --------------------------------------------------------------

const autoStart = await getPreference('autoStart', true);
if (autoStart) {
  connectAndSubscribe();
}
installRouter();

export {};  // module entry
