import {
  getStreamScanExplanationUrl,
  type ExplanationConsentInput,
} from "@workspace/api-client-react";

type ServerEvent =
  | { type: "delta"; text: string }
  | { type: "completed" }
  | { type: "error"; message: string };

function parseEventBlock(block: string): ServerEvent | undefined {
  let eventName = "message";
  const dataLines: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (!line || line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
    if (field === "event") eventName = value;
    if (field === "data") dataLines.push(value);
  }
  if (dataLines.length === 0) return undefined;

  let data: unknown;
  try {
    data = JSON.parse(dataLines.join("\n"));
  } catch {
    throw new Error("The explanation stream returned an unreadable event.");
  }
  if (!data || typeof data !== "object") {
    throw new Error("The explanation stream returned an unreadable event.");
  }

  const record = data as Record<string, unknown>;
  if (eventName === "delta" && typeof record.text === "string" && record.text.length <= 1400) {
    return { type: "delta", text: record.text };
  }
  if (eventName === "completed") return { type: "completed" };
  if (eventName === "error") {
    const message = typeof record.message === "string" && record.message.length <= 240
      ? record.message
      : "The optional explanation could not be completed. Your report is unchanged.";
    return { type: "error", message };
  }
  throw new Error("The explanation stream returned an unsupported event.");
}

function errorMessageForStatus(status: number, code: string): string {
  if (code === "EXPLANATION_ALREADY_USED") {
    return "This report's explanation request has already been used. Your report is unchanged.";
  }
  if (code === "EXPLANATION_CAPACITY_FULL" || status === 429) {
    return "The explanation service is busy. Try again shortly; your report is unchanged.";
  }
  if (status === 403 || status === 404) {
    return "This explanation request has expired. Start a new scan if you still want an explanation.";
  }
  return "The optional explanation service is unavailable. Your report is unchanged.";
}

export async function streamReportExplanation(
  scanId: string,
  explanationToken: string,
  signal: AbortSignal,
  onDelta: (text: string) => void,
  userMessage = '',
): Promise<void> {
  const body: ExplanationConsentInput = {
    consent: true,
    explanationToken,
    ...(userMessage ? { userMessage } : {}),
  };
  const response = await fetch(getStreamScanExplanationUrl(scanId), {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      accept: "text/event-stream",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
    signal,
  });

  if (!response.ok) {
    let code = "";
    try {
      const error: unknown = await response.json();
      if (error && typeof error === "object" && "code" in error) {
        code = String((error as { code?: unknown }).code ?? "");
      }
    } catch {
      // Use a generic, user-safe message if the error body is not JSON.
    }
    throw new Error(errorMessageForStatus(response.status, code));
  }
  if (
    !response.body ||
    !response.headers.get("content-type")?.toLowerCase().includes("text/event-stream")
  ) {
    throw new Error("The explanation stream is unavailable. Your report is unchanged.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let completed = false;
  try {
    while (!completed) {
      const chunk = await reader.read();
      buffer += decoder.decode(chunk.value, { stream: !chunk.done });
      if (buffer.length > 64 * 1024) {
        throw new Error("The explanation stream exceeded its size limit.");
      }
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const event = parseEventBlock(buffer.slice(0, boundary));
        buffer = buffer.slice(boundary + 2);
        if (event?.type === "delta") onDelta(event.text);
        if (event?.type === "error") throw new Error(event.message);
        if (event?.type === "completed") {
          completed = true;
          break;
        }
        boundary = buffer.indexOf("\n\n");
      }
      if (chunk.done) break;
    }
  } finally {
    reader.releaseLock();
  }
  if (!completed) {
    throw new Error("The explanation stream ended before completion. Any partial text may be incomplete.");
  }
}
