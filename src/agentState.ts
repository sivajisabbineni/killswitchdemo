export interface StoppedState {
  reason: string;
  details: Record<string, unknown>;
  stoppedAt: string;
}

let stopped: StoppedState | null = null;

export function markAgentStopped(reason: string, details: Record<string, unknown> = {}): void {
  stopped = { reason, details, stoppedAt: new Date().toISOString() };
}

export function getAgentStoppedState(): StoppedState | null {
  return stopped;
}

export function resetAgentState(): void {
  stopped = null;
}
