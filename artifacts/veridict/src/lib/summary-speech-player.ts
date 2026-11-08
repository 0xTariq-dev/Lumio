export type SummarySpeechState = "idle" | "loading" | "playing" | "stopped" | "error";

export interface SummarySpeechAudio {
  paused: boolean;
  currentTime: number;
  onended: ((event: Event) => unknown) | null;
  onerror: ((event: Event) => unknown) | null;
  play(): Promise<void>;
  pause(): void;
  removeAttribute(name: string): void;
  load(): void;
}

export interface SummarySpeechPlayerDependencies {
  requestAudio(signal: AbortSignal): Promise<Blob>;
  createObjectURL(audio: Blob): string;
  revokeObjectURL(url: string): void;
  createAudio(url: string): SummarySpeechAudio;
}

const PLAYBACK_ERROR =
  "Audio playback is unavailable. The readable summary and report are unchanged.";

export class SummarySpeechPlayer {
  private state: SummarySpeechState = "idle";
  private listeners = new Set<(state: SummarySpeechState) => void>();
  private audio: SummarySpeechAudio | null = null;
  private objectUrl: string | null = null;
  private controller: AbortController | null = null;
  private disposed = false;
  private readonly dependencies: SummarySpeechPlayerDependencies;
  private readonly onError: (message: string) => void;

  constructor(
    dependencies: SummarySpeechPlayerDependencies,
    onError: (message: string) => void,
  ) {
    this.dependencies = dependencies;
    this.onError = onError;
  }

  subscribe(listener: (state: SummarySpeechState) => void): () => void {
    this.listeners.add(listener);
    listener(this.state);
    return () => this.listeners.delete(listener);
  }

  async toggle(): Promise<void> {
    if (this.disposed || this.state === "loading") return;
    if (this.audio && !this.audio.paused) {
      this.audio.pause();
      this.audio.currentTime = 0;
      this.setState("stopped");
      return;
    }
    if (this.audio) {
      await this.playAudio(this.audio);
      return;
    }

    const controller = new AbortController();
    this.controller = controller;
    this.setState("loading");
    try {
      const blob = await this.dependencies.requestAudio(controller.signal);
      if (this.disposed || controller.signal.aborted) return;
      const url = this.dependencies.createObjectURL(blob);
      this.objectUrl = url;
      const audio = this.dependencies.createAudio(url);
      this.audio = audio;
      audio.onended = () => this.setState("stopped");
      audio.onerror = () => {
        this.onError(PLAYBACK_ERROR);
        this.setState("error");
      };
      await this.playAudio(audio);
    } catch (error) {
      if (!this.disposed && !controller.signal.aborted) {
        this.onError(error instanceof Error ? error.message : PLAYBACK_ERROR);
        this.setState("error");
      }
    } finally {
      if (this.controller === controller) this.controller = null;
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.controller?.abort();
    this.controller = null;
    if (this.audio) {
      this.audio.pause();
      this.audio.currentTime = 0;
      this.audio.onended = null;
      this.audio.onerror = null;
      this.audio.removeAttribute("src");
      this.audio.load();
      this.audio = null;
    }
    if (this.objectUrl) {
      this.dependencies.revokeObjectURL(this.objectUrl);
      this.objectUrl = null;
    }
    this.listeners.clear();
  }

  private async playAudio(audio: SummarySpeechAudio): Promise<void> {
    try {
      audio.currentTime = 0;
      await audio.play();
      if (!this.disposed) this.setState("playing");
    } catch {
      if (!this.disposed) {
        this.onError(PLAYBACK_ERROR);
        this.setState("error");
      }
    }
  }

  private setState(state: SummarySpeechState): void {
    if (this.disposed) return;
    this.state = state;
    this.listeners.forEach((listener) => listener(state));
  }
}

export function createBrowserSummarySpeechPlayer(
  requestAudio: (signal: AbortSignal) => Promise<Blob>,
  onError: (message: string) => void,
): SummarySpeechPlayer {
  return new SummarySpeechPlayer(
    {
      requestAudio,
      createObjectURL: (blob) => URL.createObjectURL(blob),
      revokeObjectURL: (url) => URL.revokeObjectURL(url),
      createAudio: (url) => new Audio(url),
    },
    onError,
  );
}
