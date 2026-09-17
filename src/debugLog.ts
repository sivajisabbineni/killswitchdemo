import crypto from 'node:crypto';

export interface CallLogEntry {
  id: string;
  timestamp: string;
  label: string;
  method: string;
  url: string;
  requestHeaders?: Record<string, string>;
  requestBody?: string;
  status?: number;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  error?: string;
}

export interface TokenEntry {
  id: string;
  timestamp: string;
  label: string;
  token: string;
  claims?: Record<string, unknown>;
}

const MAX_ENTRIES = 100;
const calls: CallLogEntry[] = [];
const tokens: TokenEntry[] = [];

export function recordCall(entry: Omit<CallLogEntry, 'id' | 'timestamp'>): void {
  calls.unshift({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...entry });
  calls.length = Math.min(calls.length, MAX_ENTRIES);
}

export function recordToken(label: string, token: string, claims?: Record<string, unknown>): void {
  tokens.unshift({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), label, token, claims });
  tokens.length = Math.min(tokens.length, MAX_ENTRIES);
}

export function getCalls(): CallLogEntry[] {
  return calls;
}

export function getTokens(): TokenEntry[] {
  return tokens;
}

export function clearHistory(): void {
  calls.length = 0;
  tokens.length = 0;
}

/**
 * Clears every call/token except those with a label in `keepLabels` — used to
 * wipe T2 onward before a fresh XAA/Chained XAA/tool-call run while leaving
 * the T1 login step visible, since the session (and its tokens) is still
 * valid even though this run doesn't touch login.
 */
export function clearHistoryExceptLabels(keepLabels: string[]): void {
  for (let i = calls.length - 1; i >= 0; i--) {
    if (!keepLabels.includes(calls[i].label)) calls.splice(i, 1);
  }
  for (let i = tokens.length - 1; i >= 0; i--) {
    if (!keepLabels.includes(tokens[i].label)) tokens.splice(i, 1);
  }
}

export function clearCallsByLabel(labels: string[]): void {
  for (let i = calls.length - 1; i >= 0; i--) {
    if (labels.includes(calls[i].label)) calls.splice(i, 1);
  }
}

export function clearTokensByLabel(labels: string[]): void {
  for (let i = tokens.length - 1; i >= 0; i--) {
    if (labels.includes(tokens[i].label)) tokens.splice(i, 1);
  }
}
