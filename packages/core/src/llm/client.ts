export type LLMProvider = "anthropic" | "ollama";

export interface LLMConfig {
  /** Explicit provider. Auto-detected from apiKey/baseUrl/env if omitted. */
  provider?: LLMProvider;
  /** Anthropic API key. Ignored for ollama. */
  apiKey?: string;
  /** Ollama server URL (default http://127.0.0.1:11434, or OLLAMA_BASE_URL). Ignored for anthropic. */
  baseUrl?: string;
  /** Model name. Provider-specific default if omitted. */
  model?: string;
}

export interface LLMCallParams {
  system?: string;
  prompt: string;
  maxTokens?: number;
  /** Ask the provider to constrain output to valid JSON, where supported. */
  json?: boolean;
}

const DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001";
const DEFAULT_OLLAMA_MODEL = "llama3.2";
const DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434";
const ANTHROPIC_BASE_URL = "https://api.anthropic.com";

interface ResolvedLLM {
  provider: LLMProvider;
  apiKey?: string;
  baseUrl: string;
  model: string;
}

/**
 * Resolve an LLMConfig into a concrete provider + credentials, or undefined if
 * nothing is configured (no key, no explicit provider/baseUrl, no relevant env
 * var). Callers use this to decide whether to skip an LLM-backed check entirely
 * rather than fail loudly — the same "gracefully unavailable" contract the
 * policy compiler and intent reconciler have always had.
 */
export function resolveLLMConfig(cfg: LLMConfig = {}): ResolvedLLM | undefined {
  const provider =
    cfg.provider ??
    (cfg.apiKey ?? process.env.ANTHROPIC_API_KEY
      ? "anthropic"
      : (cfg.baseUrl ?? process.env.OLLAMA_BASE_URL)
        ? "ollama"
        : undefined);

  if (!provider) return undefined;

  if (provider === "anthropic") {
    const apiKey = cfg.apiKey ?? process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return undefined;
    return {
      provider,
      apiKey,
      baseUrl: cfg.baseUrl ?? ANTHROPIC_BASE_URL,
      model: cfg.model ?? DEFAULT_ANTHROPIC_MODEL,
    };
  }

  return {
    provider,
    baseUrl: cfg.baseUrl ?? process.env.OLLAMA_BASE_URL ?? DEFAULT_OLLAMA_BASE_URL,
    model: cfg.model ?? process.env.OLLAMA_MODEL ?? DEFAULT_OLLAMA_MODEL,
  };
}

/**
 * Call the configured LLM provider and return the raw text response. Shared by
 * the policy compiler and the intent reconciler so adding a provider (e.g.
 * Ollama, for a zero-API-key local option) happens in exactly one place.
 */
export async function callLLM(cfg: LLMConfig, params: LLMCallParams): Promise<string> {
  const resolved = resolveLLMConfig(cfg);
  if (!resolved) {
    throw new Error(
      "No LLM configured — set ANTHROPIC_API_KEY, or run Ollama locally " +
        '(`ollama serve`) and set OLLAMA_BASE_URL, or pass an explicit { provider }.',
    );
  }
  return resolved.provider === "anthropic"
    ? callAnthropic(resolved, params)
    : callOllama(resolved, params);
}

async function callAnthropic(cfg: ResolvedLLM, params: LLMCallParams): Promise<string> {
  const res = await fetch(`${cfg.baseUrl}/v1/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": cfg.apiKey!,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: cfg.model,
      max_tokens: params.maxTokens ?? 1500,
      ...(params.system ? { system: params.system } : {}),
      messages: [{ role: "user", content: params.prompt }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic call failed: ${res.status} ${await res.text()}`);
  const data = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
  return data.content?.find((b) => b.type === "text")?.text ?? "";
}

async function callOllama(cfg: ResolvedLLM, params: LLMCallParams): Promise<string> {
  const messages = [
    ...(params.system ? [{ role: "system", content: params.system }] : []),
    { role: "user", content: params.prompt },
  ];
  let res: Response;
  try {
    res = await fetch(`${cfg.baseUrl}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: cfg.model,
        messages,
        stream: false,
        ...(params.json ? { format: "json" } : {}),
      }),
    });
  } catch (err) {
    throw new Error(
      `Ollama not reachable at ${cfg.baseUrl} — is \`ollama serve\` running, and is ` +
        `\`${cfg.model}\` pulled (\`ollama pull ${cfg.model}\`)? (${err instanceof Error ? err.message : String(err)})`,
    );
  }
  if (!res.ok) throw new Error(`Ollama call failed: ${res.status} ${await res.text()}`);
  const data = (await res.json()) as { message?: { content?: string } };
  return data.message?.content ?? "";
}
