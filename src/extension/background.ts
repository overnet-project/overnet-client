import { Agent, type State } from '../agent/agent.ts';
import { api } from './api.ts';
import { installBridge } from './bridge.ts';

const ready = Agent.open({
  async read() { return (await api.storage.local.get('overnetAgent')).overnetAgent; },
  async write(state: State) { await api.storage.local.set({ overnetAgent: state }); },
});
installBridge(api, ready);
