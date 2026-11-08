export type PublicSseEvent = {
  id?: string;
  event: string;
  data: unknown;
};

const EVENT_ID_PATTERN = /^\d{1,10}$/;

export function safeLastEventId(value: string | undefined): string | undefined {
  return value && EVENT_ID_PATTERN.test(value) ? value : undefined;
}

export function serializePublicSseEvent(event: PublicSseEvent): string {
  if (event.id !== undefined && !EVENT_ID_PATTERN.test(event.id)) {
    throw new Error('Invalid server-sent event ID');
  }
  const idLine = event.id === undefined ? '' : `id: ${event.id}\n`;
  return `${idLine}event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`;
}
