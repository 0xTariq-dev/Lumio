export const MAX_SUMMARY_SPEECH_AUDIO_BYTES = 6 * 1024 * 1024;

export async function requestSummarySpeech(
  scanId: string,
  explanationToken: string,
  summary: string,
  signal: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<Blob> {
  const response = await fetcher(
    `/api/scans/${encodeURIComponent(scanId)}/explanation/speech`,
    {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        accept: "audio/mpeg",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        consent: true,
        explanationToken,
        summary,
      }),
      signal,
    },
  );
  if (!response.ok) {
    throw new Error(
      "Spoken audio could not be prepared. The readable summary and report are unchanged.",
    );
  }

  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("audio/mpeg")) {
    throw new Error(
      "Spoken audio was unavailable. The readable summary and report are unchanged.",
    );
  }
  const audio = await response.blob();
  if (!audio.size || audio.size > MAX_SUMMARY_SPEECH_AUDIO_BYTES) {
    throw new Error(
      "Spoken audio was unavailable. The readable summary and report are unchanged.",
    );
  }
  return audio;
}
