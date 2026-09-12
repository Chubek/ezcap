/**
 * Options page: extension preferences.
 *
 * Deliberately minimal. The daemon's privacy policy (metadata-only,
 * redaction) is NOT configurable from the extension beyond what the
 * daemon's set_policy operation allows, and metadata-only can never be
 * disabled. This page exposes local display preferences only.
 */

import { getPreference, setPreference } from '../../shared/src/storage';

interface Elements {
  autoStart: HTMLInputElement;
  eventLimit: HTMLSelectElement;
  save: HTMLButtonElement;
  status: HTMLParagraphElement;
}

function query(): Elements | null {
  const autoStart = document.getElementById('auto-start') as HTMLInputElement | null;
  const eventLimit = document.getElementById('event-limit') as HTMLSelectElement | null;
  const save = document.getElementById('save') as HTMLButtonElement | null;
  const status = document.getElementById('status') as HTMLParagraphElement | null;
  if (!autoStart || !eventLimit || !save || !status) {
    return null;
  }
  return { autoStart, eventLimit, save, status };
}

async function load(): Promise<void> {
  const els = query();
  if (!els) {
    return;
  }
  els.autoStart.checked = await getPreference('autoStart', true);
  const limit = await getPreference('eventLimit', 100);
  els.eventLimit.value = String(limit);
}

async function save(els: Elements): Promise<void> {
  await setPreference('autoStart', els.autoStart.checked);
  await setPreference('eventLimit', Number(els.eventLimit.value));
  els.status.textContent = 'saved';
  setTimeout(() => (els.status.textContent = ''), 1500);
}

document.addEventListener('DOMContentLoaded', () => {
  const els = query();
  if (!els) {
    return;
  }
  void load();
  els.save.addEventListener('click', () => void save(els));
});
