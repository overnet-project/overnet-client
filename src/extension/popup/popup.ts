import { api } from '../api.ts';
import type { AgentView } from '../../agent/agent.ts';
import { object } from '../../protocol/errors.ts';
const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;
const input = (id: string) => $<HTMLInputElement>(id);
const select = $<HTMLSelectElement>('#identity');
const port = api.runtime.connect({ name: 'overnet-settings' });
const pending = new Map<string, { resolve(value: unknown): void; reject(error: Error): void }>();
let view: AgentView = { identities: [], policies: [] };
let backupURL: string | undefined;
const request = <T>(method: string, params: Record<string, unknown> = {}): Promise<T> => new Promise((resolve, reject) => {
  const id = crypto.randomUUID();
  pending.set(id, { resolve: (value) => resolve(value as T), reject });
  port.postMessage({ id, method, params });
});
port.onMessage.addListener((message) => {
  if (!object(message) || typeof message.id !== 'string') return;
  const job = pending.get(message.id); if (!job) return;
  pending.delete(message.id);
  if (typeof message.error === 'string') job.reject(new Error(message.error)); else job.resolve(message.result);
});
port.onDisconnect.addListener(() => {
  for (const job of pending.values()) job.reject(new Error('Overnet disconnected. Open this window again.'));
  pending.clear();
});
function clearBackup() {
  if (backupURL) URL.revokeObjectURL(backupURL);
  backupURL = undefined; $<HTMLTextAreaElement>('#backup').value = ''; $('#backup-result').hidden = true;
}
function selected() {
  const identity = view.identities.find((i) => i.id === select.value);
  $('#state').textContent = identity?.unlocked ? 'Unlocked for this browser session.' : 'Locked.';
  $('#pubkey').textContent = identity?.pubkey ?? '';
  $('#unlock-form').hidden = !!identity?.unlocked;
  $('#backup-section').hidden = !identity?.unlocked;
  clearBackup();
}
function render(next: AgentView) {
  view = next;
  const previous = select.value;
  select.replaceChildren(...view.identities.map((i) => new Option(i.label, i.id)));
  if (view.identities.some((i) => i.id === previous)) select.value = previous;
  $('#existing').hidden = !view.identities.length;
  $<HTMLDetailsElement>('#add-section').open = !view.identities.length;
  $('#policies').replaceChildren(...view.policies.map((p) => {
    const item = document.createElement('li');
    const identity = view.identities.find((i) => i.id === p.identityId);
    item.textContent = `${identity?.label}: ${p.origin} → ${p.scope}${p.relay ? ` (delegation to ${p.relay}, up to 24 hours)` : ''}`;
    return item;
  }));
  if (!view.policies.length) $('#policies').textContent = 'No remembered access.';
  selected();
}
async function run(action: () => Promise<void>) {
  const buttons = [...document.querySelectorAll<HTMLButtonElement>('button')];
  buttons.forEach((b) => { b.disabled = true; }); $('#status').textContent = 'Working…';
  try { await action(); } catch (error) { $('#status').textContent = error instanceof Error ? error.message : 'Unable to complete this action.'; }
  finally { buttons.forEach((b) => { b.disabled = false; }); }
}
select.addEventListener('change', selected);
$('#create-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void run(async () => {
    const password = input('#new-password').value;
    if (password !== input('#confirm-password').value) throw new Error('The passphrases do not match.');
    try {
      render(await request<AgentView>('create', { label: input('#label').value, password,
        key: $<HTMLTextAreaElement>('#key').value, importPassword: input('#import-password').value }));
      $<HTMLFormElement>('#create-form').reset();
      $('#status').textContent = 'Identity saved. Create a backup, then open your application.';
    } finally {
      for (const id of ['#new-password', '#confirm-password', '#import-password', '#key']) input(id).value = '';
    }
  });
});
$('#unlock-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void run(async () => {
    try { render(await request<AgentView>('unlock', { identityId: select.value, password: input('#password').value })); $('#status').textContent = 'Identity unlocked.'; }
    finally { input('#password').value = ''; }
  });
});
$('#lock').addEventListener('click', () => void run(async () => {
  render(await request<AgentView>('lock')); $('#status').textContent = 'Identities locked.';
}));
$('#forget').addEventListener('click', () => void run(async () => {
  render(await request<AgentView>('forget')); $('#status').textContent = 'Remembered access removed. Already issued sessions expire at their stated time.';
}));
$('#backup-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void run(async () => {
    const password = input('#backup-password').value;
    if (password !== input('#backup-confirm').value) throw new Error('The backup passphrases do not match.');
    try {
      const { backup } = await request<{ backup: string }>('backup', { identityId: select.value, password });
      clearBackup(); $<HTMLTextAreaElement>('#backup').value = backup;
      backupURL = URL.createObjectURL(new Blob([`${backup}\n`], { type: 'text/plain' }));
      const link = $<HTMLAnchorElement>('#download'); link.href = backupURL; link.download = 'overnet-identity.ncryptsec';
      $('#backup-result').hidden = false; $('#status').textContent = 'Encrypted backup ready to save.';
    } finally { input('#backup-password').value = ''; input('#backup-confirm').value = ''; }
  });
});
window.addEventListener('pagehide', () => { clearBackup(); port.disconnect(); });
$('#version').textContent = `Overnet ${api.runtime.getManifest().version}`;
void run(async () => { render(await request<AgentView>('status')); $('#status').textContent = view.identities.length ? 'Your identity keys stay on this computer.' : 'Add your first identity to get started.'; });
