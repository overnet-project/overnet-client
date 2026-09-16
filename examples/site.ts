import { OvernetClient } from '../src/web/index.ts';
const client = new OvernetClient();
const button = document.querySelector<HTMLButtonElement>('#connect')!;
const status = document.querySelector<HTMLElement>('#status')!;
button.addEventListener('click', async () => {
  button.disabled = true;
  status.textContent = 'Approve sign-in in Overnet.';
  try {
    await client.info();
    const challenge = await (await fetch('/challenge')).json();
    const result = await client.authenticate(challenge);
    const response = await fetch('/authenticate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(result) });
    if (!response.ok) throw new Error('Service rejected the authentication response.');
    const { identity } = await response.json();
    status.textContent = `Signed in as ${identity}`;
    status.dataset.state = 'signed-in';
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : 'Sign-in failed.';
    status.dataset.state = 'failed';
  } finally { button.disabled = false; }
});
