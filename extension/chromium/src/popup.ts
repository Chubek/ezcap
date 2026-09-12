/**
 * Popup: recent events and connection status.
 *
 * Shows the newest events from the bounded local ring with their
 * attribution confidence bands, plus daemon connection state and a
 * clear-data action. No event detail beyond metadata is displayed,
 * because none exists.
 */

import { summarizeEvent } from '../../shared/src/event-model';
import { confidenceBand } from '../../shared/src/protocol';
import type { EzcapEvent } from '../../shared/src/protocol';

type RuntimeWithMessages = {
  runtime?: {
    sendMessage(message: unknown): Promise<unknown>;
  };
};

function getRuntime(): RuntimeWithMessages | null {
  const b = (globalThis as Record<string, unknown>).browser ?? undefined;
  if (b && (b as RuntimeWithMessages).runtime) {
    return b as RuntimeWithMessages;
  }
  const c = (globalThis as Record<string, unknown>).chrome ?? undefined;
  if (c && (c as RuntimeWithMessages).runtime) {
    return c as RuntimeWithMessages;
  }
  return null;
}

interface PopupState {
  events: EzcapEvent[];
  connected: boolean;
}

async function fetchState(): Promise<PopupState> {
  const runtime = getRuntime();
  if (!runtime?.runtime) {
    return { events: [], connected: false };
  }
  const eventsReply = await runtime.runtime.sendMessage({ type: 'ezcap:getEvents', limit: 50 });
  const statusReply = await runtime.runtime.sendMessage({ type: 'ezcap:getStatus' });
  const events = (eventsReply as { events?: EzcapEvent[] })?.events ?? [];
  const connected = (statusReply as { connected?: boolean })?.connected ?? false;
  return { events, connected };
}

function render(state: PopupState): void {
  const root = document.getElementById('ezcap-root');
  if (!root) {
    return;
  }
  root.textContent = '';

  const status = document.createElement('p');
  status.className = 'status ' + (state.connected ? 'ok' : 'bad');
  status.textContent = state.connected
    ? 'daemon connected'
    : 'daemon not connected';
  root.appendChild(status);

  const list = document.createElement('ul');
  list.className = 'events';
  for (const event of state.events) {
    const item = document.createElement('li');
    item.className = 'event event-' + event.event_type;

    const summary = document.createElement('span');
    summary.className = 'summary';
    summary.textContent = summarizeEvent(event);
    item.appendChild(summary);

    const meta = document.createElement('span');
    meta.className = 'meta';
    const band = confidenceBand(event.confidence);
    meta.textContent = `${band} · ${event.timestamp.slice(11, 19)}`;
    item.appendChild(meta);

    list.appendChild(item);
  }
  if (state.events.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty';
    empty.textContent = 'no events yet';
    list.appendChild(empty);
  }
  root.appendChild(list);

  const actions = document.createElement('div');
  actions.className = 'actions';
  const clear = document.createElement('button');
  clear.textContent = 'Clear stored events';
  clear.addEventListener('click', async () => {
    const runtime = getRuntime();
    await runtime?.runtime?.sendMessage({ type: 'ezcap:clear' });
    void render(await fetchState());
  });
  actions.appendChild(clear);
  root.appendChild(actions);
}

void fetchState().then(render);
