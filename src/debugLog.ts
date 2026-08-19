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
