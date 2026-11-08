export type PublicWorkerFailureEvent = {
  event: "failed";
  data: {
    code: "ANALYSIS_FAILED";
    message: string;
    retryable: true;
  };
};

export function toPublicWorkerFailureEvent(
  _workerPayload: unknown,
): PublicWorkerFailureEvent {
  return {
    event: "failed",
    data: {
      code: "ANALYSIS_FAILED",
      message: "This analysis could not be completed. No report is available.",
      retryable: true,
    },
  };
}

export function isTerminalAnalysisEvent(event: string): boolean {
  return event === "completed" || event === "failed";
}
