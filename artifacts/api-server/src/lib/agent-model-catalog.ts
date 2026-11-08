import { z } from "zod";
import { DEFAULT_VULTR_INFERENCE_MODEL } from "./serverless-inference.ts";

export const AGENT_CHAT_MODEL_OPTIONS = [
  {
    id: "qwen3.8-flash-next",
    label: "Qwen 3.8 Flash Next",
    description: "Fast default for short agent proposals.",
  },
  {
    id: "qwen3.8-27b",
    label: "Qwen 3.8 27B",
    description: "Larger general-purpose Qwen chat model.",
  },
  {
    id: "deepseek-v4.1-flash-1017",
    label: "DeepSeek V4.1 Flash",
    description: "Flash model for concise agent decisions.",
  },
  {
    id: "glm-5.2",
    label: "GLM 5.2",
    description: "General-purpose chat alternative.",
  },
] as const;

export type AgentChatModelOption = (typeof AGENT_CHAT_MODEL_OPTIONS)[number];

const catalogResponseSchema = z.object({
  data: z.array(
    z.object({
      id: z.string().min(1).max(100),
    }).passthrough(),
  ).max(500),
}).passthrough();

const MODEL_CATALOG_URL = "https://api.vultrinference.com/v1/models";
const MODEL_CATALOG_TTL_MS = 5 * 60 * 1000;
const MAX_CATALOG_BYTES = 256 * 1024;
const MODEL_CATALOG_TIMEOUT_MS = 4_000;

export function isKnownAgentChatModelId(value: string): value is AgentChatModelOption["id"] {
  return AGENT_CHAT_MODEL_OPTIONS.some((model) => model.id === value);
}

export function defaultAgentChatModelId(
  models: readonly AgentChatModelOption[],
  preferredModel = DEFAULT_VULTR_INFERENCE_MODEL,
): string | null {
  return models.find((model) => model.id === preferredModel)?.id
    ?? models.find((model) => model.id === DEFAULT_VULTR_INFERENCE_MODEL)?.id
    ?? models[0]?.id
    ?? null;
}

export function createAgentModelCatalogLoader(options: {
  fetcher?: typeof fetch;
  now?: () => number;
  ttlMs?: number;
} = {}): () => Promise<AgentChatModelOption[]> {
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlMs ?? MODEL_CATALOG_TTL_MS;
  let cachedModels: AgentChatModelOption[] | null = null;
  let cacheExpiresAt = 0;
  let inFlight: Promise<AgentChatModelOption[]> | null = null;

  return async () => {
    if (cachedModels && now() < cacheExpiresAt) return cachedModels;
    if (inFlight) return inFlight;

    inFlight = (async () => {
      const response = await fetcher(MODEL_CATALOG_URL, {
        method: "GET",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(MODEL_CATALOG_TIMEOUT_MS),
      });
      if (!response.ok) {
        throw new Error(`Vultr model catalog returned HTTP ${response.status}`);
      }
      const declaredLength = Number(response.headers.get("content-length") ?? 0);
      if (Number.isFinite(declaredLength) && declaredLength > MAX_CATALOG_BYTES) {
        throw new Error("Vultr model catalog exceeded its size limit");
      }

      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > MAX_CATALOG_BYTES) {
        throw new Error("Vultr model catalog exceeded its size limit");
      }
      let decoded: unknown;
      try {
        decoded = JSON.parse(text);
      } catch {
        throw new Error("Vultr model catalog returned malformed JSON");
      }
      const parsed = catalogResponseSchema.safeParse(decoded);
      if (!parsed.success) {
        throw new Error("Vultr model catalog returned an unexpected response");
      }

      const availableIds = new Set(parsed.data.data.map((model) => model.id));
      const available = AGENT_CHAT_MODEL_OPTIONS.filter((model) => availableIds.has(model.id));
      cachedModels = available;
      cacheExpiresAt = now() + ttlMs;
      return available;
    })();

    try {
      return await inFlight;
    } finally {
      inFlight = null;
    }
  };
}

export const getAvailableAgentChatModels = createAgentModelCatalogLoader();
