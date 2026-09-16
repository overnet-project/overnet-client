import { api } from '../api.ts';
import type { AgentView } from '../../agent/agent.ts';
type ApprovalMessage = AgentView & { error?: string; origin: string; challenge: {
  scope: string; delegate_pubkey?: string; relay_url?: string; expires_at?: number;
} };
const port = api.runtime.connect({ name: 'overnet-approval' });
const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;
let identities: AgentView['identities'] = [];
const identity = $<HTMLSelectElement>('#identity');
function selection() {
  const selected = identities.find((i) => i.id === identity.value);
  $('#unlock').hidden = !!selected?.unlocked;
  $<HTMLInputElement>('#password').required = !selected?.unlocked;
  $<HTMLButtonElement>('#approve').disabled = !selected;
}
port.onMessage.addListener((value) => {
  const message = value as ApprovalMessage;
  if (message.error) {
    $('#status').textContent = message.error; identity.disabled = false;
    $<HTMLInputElement>('#password').value = ''; selection(); return;
  }
  identities = message.identities;
  $('#origin').textContent = message.origin;
  $('#scope').textContent = message.challenge.scope;
  const previous = identity.value;
  identity.replaceChildren(...identities.map((i) => new Option(i.label, i.id)));
  if (identities.some((i) => i.id === previous)) identity.value = previous;
  if (message.challenge.delegate_pubkey) {
    $('#delegation').textContent = `Allow this service to act for this session until ${new Date(Number(message.challenge.expires_at) * 1000).toLocaleString()}.`;
    $('#delegation').hidden = false; $('#session').hidden = false;
    $('#relay').textContent = message.challenge.relay_url ?? ''; $('#delegate').textContent = message.challenge.delegate_pubkey;
    $('#remember-text').textContent = 'Remember access for this identity, website, service, and authority relay, including sessions up to 24 hours.';
  }
  $('form').hidden = !identities.length;
  $('#status').textContent = identities.length ? 'Approve only if you intended to sign in to this service.' : 'Add an identity in Manage identities, then refresh this window.';
  selection();
});
identity.addEventListener('change', selection);
$('form').addEventListener('submit', (event) => {
  event.preventDefault();
  $<HTMLButtonElement>('#approve').disabled = true; identity.disabled = true;
  $('#status').textContent = 'Signing on this computer…';
  const password = $<HTMLInputElement>('#password');
  port.postMessage({ approve: true, identityId: identity.value, password: password.value, remember: $<HTMLInputElement>('#remember').checked });
  password.value = '';
});
$('#deny').addEventListener('click', () => port.postMessage({ approve: false }));
$('#manage').addEventListener('click', () => void api.tabs.create({ url: api.runtime.getURL('popup/index.html') }));
$('#refresh').addEventListener('click', () => port.postMessage({ refresh: true }));
port.onDisconnect.addListener(() => window.close());
