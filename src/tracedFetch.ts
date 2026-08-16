import { recordCall } from './debugLog';

function normalizeHeaders(headers: RequestInit['headers']): Record<string, string> | undefined {
  if (!headers) return undefined;
  if (headers instanceof Headers) return Object.fromEntries(headers.entries());
  if (Array.isArray(headers)) return Object.fromEntries(headers);
  return { ...headers } as Record<string, string>;
}

/**
 * Wraps fetch so every outbound call this agent makes (login, ID-JAG
 * exchange, resource token exchange, resource API calls) shows up in the
 * /debug page with its request/response headers and bodies — including on
 * failure, since Okta's error responses are the most useful diagnostic here.
 */
export async function tracedFetch(label: string, url: string, init: RequestInit = {}): Promise<Response> {
  const method = init.method || 'GET';
  const requestHeaders = normalizeHeaders(init.headers);
  const requestBody =
    typeof init.body === 'string'
      ? init.body
      : init.body instanceof URLSearchParams
        ? init.body.toString()
        : undefined;

  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (err) {
    recordCall({ label, method, url, requestHeaders, requestBody, error: (err as Error).message });
    throw err;
  }

  const responseBody = await res
    .clone()
    .text()
    .catch(() => '<unreadable body>');
  const responseHeaders = Object.fromEntries(res.headers.entries());
  recordCall({ label, method, url, requestHeaders, requestBody, status: res.status, responseHeaders, responseBody });
  return res;
}
