// Minimal Mailpit REST client (https://mailpit.axllent.org/docs/api-v1/). Mailpit is the local SMTP sink (docker-compose).
const base = (): string => (process.env.E2E_MAILPIT_URL ?? 'http://127.0.0.1:8025').replace(/\/+$/, '');

interface SearchResult {
  messages_count: number;
  messages: { ID: string; Subject: string }[];
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${base()}${path}`);
  if (!res.ok) throw new Error(`Mailpit ${path.split('?')[0]} answered ${res.status}`);
  return (await res.json()) as T;
}

export const search = (query: string) => getJson<SearchResult>(`/api/v1/search?query=${encodeURIComponent(query)}&limit=1000`);

/** Poll until at least `min` messages match; returns the final result. Never prints message bodies (they carry tokens). */
export async function waitForMessages(query: string, min = 1, timeoutMs = 90_000): Promise<SearchResult> {
  const deadline = Date.now() + timeoutMs;
  let last: SearchResult = { messages_count: 0, messages: [] };
  while (Date.now() < deadline) {
    last = await search(query);
    if (last.messages_count >= min) return last;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`Mailpit: expected >= ${min} message(s) for the query, found ${last.messages_count} after ${timeoutMs} ms`);
}

export async function messageText(id: string): Promise<string> {
  const m = await getJson<{ Text: string }>(`/api/v1/message/${encodeURIComponent(id)}`);
  return m.Text;
}

/** Text of the first message matching the query, waiting for it to arrive. */
export async function firstMessageText(query: string): Promise<string> {
  const r = await waitForMessages(query, 1);
  return messageText(r.messages[0]!.ID);
}
