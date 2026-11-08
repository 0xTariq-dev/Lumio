import { useEffect, useRef, useState } from "react";
import { LoaderCircle, Play, Square } from "lucide-react";
import {
  createBrowserSummarySpeechPlayer,
  type SummarySpeechPlayer,
  type SummarySpeechState,
} from "@/lib/summary-speech-player";
import { requestSummarySpeech } from "@/lib/summary-speech";

export function SummarySpeechControl({
  scanId,
  explanationToken,
  summary,
}: {
  scanId: string;
  explanationToken: string;
  summary: string;
}) {
  const playerRef = useRef<SummarySpeechPlayer | null>(null);
  const [state, setState] = useState<SummarySpeechState>("idle");
  const [error, setError] = useState("");
  const errorId = `speech-status-${scanId}`;
  const disclosureId = `speech-disclosure-${scanId}`;

  useEffect(() => {
    const player = createBrowserSummarySpeechPlayer(
      (signal) =>
        requestSummarySpeech(scanId, explanationToken, summary, signal),
      setError,
    );
    playerRef.current = player;
    const unsubscribe = player.subscribe(setState);
    return () => {
      unsubscribe();
      player.dispose();
      if (playerRef.current === player) playerRef.current = null;
    };
  }, [scanId, explanationToken, summary]);

  const isPlaying = state === "playing";
  const isLoading = state === "loading";
  const label = isLoading
    ? "Preparing spoken summary"
    : isPlaying
      ? "Stop spoken summary"
      : "Play spoken summary";

  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1">
      <button
        type="button"
        onClick={() => void playerRef.current?.toggle()}
        disabled={isLoading}
        aria-label={label}
        aria-describedby={error ? `${disclosureId} ${errorId}` : disclosureId}
        aria-pressed={isPlaying}
        aria-busy={isLoading}
        data-testid={`button-summary-speech-${scanId}`}
        className="inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-md border border-input bg-background px-3 text-sm font-medium hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-wait disabled:opacity-60 sm:w-auto"
      >
        {isLoading ? (
          <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
        ) : isPlaying ? (
          <Square className="size-3.5 fill-current" aria-hidden="true" />
        ) : (
          <Play className="size-4 fill-current" aria-hidden="true" />
        )}
        {isLoading
          ? "Preparing audio…"
          : isPlaying
            ? "Stop audio"
            : "Play summary"}
      </button>
      <p id={disclosureId} className="text-xs leading-5 text-muted-foreground">
        Clicking Play sends this summary to Vultr for speech generation. The
        audio stays in this tab.
      </p>
      {error && (
        <p
          id={errorId}
          className="basis-full text-xs leading-5 text-muted-foreground"
          role="status"
          aria-live="polite"
          data-testid={`status-summary-speech-${scanId}`}
        >
          {error}
        </p>
      )}
    </div>
  );
}
