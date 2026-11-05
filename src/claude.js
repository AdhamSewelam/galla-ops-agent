// AI writer: summaries and recommendations from stored facts only. It has no tools and cannot trigger actions.
// Uses Claude if ANTHROPIC_API_KEY is set, otherwise Google Gemini (free tier) if GEMINI_API_KEY is set.
// Output is JSON that code renders; nothing the AI returns is ever executed.
import Anthropic from '@anthropic-ai/sdk';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const PROMPT_PATH = fileURLToPath(new URL('../prompts/agent.md', import.meta.url));

export function createClaude(config, { sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  if (!config.features.ai) return null;
  const system = fs.readFileSync(PROMPT_PATH, 'utf8');

  if (config.features.aiProvider === 'anthropic') {
    const client = new Anthropic({ apiKey: config.ANTHROPIC_API_KEY });
    return {
      provider: 'anthropic',
      async json(task, { maxTokens = 2000 } = {}) {
        const res = await client.messages.create({
          model: config.ANTHROPIC_MODEL,
          max_tokens: maxTokens,
          system,
          messages: [{ role: 'user', content: task }],
        });
        return parseJson(res.content.filter((b) => b.type === 'text').map((b) => b.text).join(''));
      },
    };
  }

  // Free-tier Gemini is often "overloaded" (503) or rate-limited (429): retry with backoff,
  // and fall back to the lighter model before giving up.
  const models = [config.GEMINI_MODEL, ...config.GEMINI_FALLBACK_MODELS.split(',').map((m) => m.trim()).filter(Boolean)];

  async function callOnce(model, task, maxTokens, timeoutMs = 120000) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-goog-api-key': config.GEMINI_API_KEY },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: system }] },
          contents: [{ role: 'user', parts: [{ text: task }] }],
          // extra headroom: Gemini "thinking" models spend output tokens before answering
          generationConfig: { responseMimeType: 'application/json', maxOutputTokens: Math.max(maxTokens, 8192), temperature: 0.7 },
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      return { retryable: true, error: `${model}: ${e.message}` };
    }
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      const retryable = [429, 500, 502, 503, 504].includes(res.status);
      return { retryable, error: `${model}: ${json.error?.message || res.status}` };
    }
    const text = (json.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
    if (!text) return { retryable: true, error: `${model}: no text (${json.candidates?.[0]?.finishReason || 'unknown'})` };
    return { text };
  }

  return {
    provider: 'gemini',
    // interactive = someone is waiting (Team chat/meetings): lighter model first and
    // short retries, so a busy free tier answers in seconds or fails clearly. Background
    // jobs (drafts, SEO, reviews) keep the patient 10s/30s/60s schedule.
    async json(task, { maxTokens = 2000, interactive = false } = {}) {
      const errors = [];
      const order = interactive ? [...models.slice(1), models[0]] : models;
      const waits = interactive ? [2000, 5000] : [10000, 30000, 60000];
      for (const model of order) {
        for (let attempt = 0; attempt < waits.length; attempt++) {
          const r = await callOnce(model, task, maxTokens, interactive ? 45000 : 120000);
          if (r.text) return parseJson(r.text);
          errors.push(r.error);
          if (!r.retryable) break;
          await sleep(waits[attempt]);
        }
      }
      throw new Error(interactive ? `The AI is busy right now (free Gemini tier). Try again in a minute. (${errors.slice(-1)[0] || 'no answer'})` : `Gemini API failed: ${errors.slice(-2).join(' | ')}`);
    },
  };
}

export function parseJson(text) {
  const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const start = cleaned.search(/[[{]/);
    const end = Math.max(cleaned.lastIndexOf('}'), cleaned.lastIndexOf(']'));
    if (start >= 0 && end > start) return JSON.parse(cleaned.slice(start, end + 1));
    throw new Error('AI did not return valid JSON');
  }
}
