import path from 'node:path';
import { ScrubEngine } from './core/engine.js';
import type {
  Finding,
  InputFormat,
  PlainVaultFile,
  ScrubCategory,
  ScrubOptions,
  ScrubResult,
  ScrubStats,
  VaultFile
} from './core/types.js';
import {
  deserializeVault,
  loadVaultFromFile,
  restoreFromVault,
  saveVaultToFile,
  serializeVault
} from './core/vault.js';
import { scrubEnvString } from './rewriters/env.js';
import { scrubHarObject, scrubHarString } from './rewriters/har.js';
import { scrubJsonlString, scrubJsonString, scrubJsonValue } from './rewriters/json.js';
import { scrubJwtToken } from './rewriters/jwt.js';
import { scrubTextString } from './rewriters/text.js';

export function detectFormat(
  content: string,
  filePath?: string
): Exclude<InputFormat, 'auto'> {
  if (filePath) {
    const base = path.basename(filePath).toLowerCase();
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.har') return 'har';
    if (ext === '.jsonl' || ext === '.ndjson') return 'jsonl';
    if (base === '.env' || base.startsWith('.env.') || ext === '.env') return 'env';
  }

  const trimmed = content.trim();
  if (!trimmed) return 'text';

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (
        parsed &&
        typeof parsed === 'object' &&
        !Array.isArray(parsed) &&
        parsed.log &&
        typeof parsed.log === 'object' &&
        Array.isArray((parsed.log as Record<string, unknown>).entries)
      ) {
        return 'har';
      }
      return 'json';
    } catch {
      // Check if it's JSONL (multiple lines of JSON objects)
      const nonEmptyLines = trimmed
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      if (nonEmptyLines.length > 1 && nonEmptyLines[0]?.startsWith('{')) {
        try {
          JSON.parse(nonEmptyLines[0]);
          return 'jsonl';
        } catch {
          // Not JSONL
        }
      }
    }
  }

  // Check if it looks like a .env file
  const lines = trimmed
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  if (
    lines.length > 0 &&
    lines.every((l) => /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l))
  ) {
    return 'env';
  }

  return 'text';
}

export function scrubTrace(
  content: string,
  options: ScrubOptions & { format?: InputFormat; filePath?: string } = {}
): { result: ScrubResult; engine: ScrubEngine } {
  const engine = new ScrubEngine(options);
  const resolvedFormat =
    !options.format || options.format === 'auto'
      ? detectFormat(content, options.filePath)
      : options.format;

  let output: string;
  switch (resolvedFormat) {
    case 'har':
      output = scrubHarString(content, engine);
      break;
    case 'json':
      output = scrubJsonString(content, engine);
      break;
    case 'jsonl':
      output = scrubJsonlString(content, engine);
      break;
    case 'env':
      output = scrubEnvString(content, engine);
      break;
    case 'text':
    default:
      output = scrubTextString(content, engine);
      break;
  }

  return {
    result: {
      output,
      format: resolvedFormat,
      findings: engine.getFindings(),
      stats: engine.getStats()
    },
    engine
  };
}

export {
  ScrubEngine,
  scrubHarObject,
  scrubHarString,
  scrubJsonValue,
  scrubJsonString,
  scrubJsonlString,
  scrubEnvString,
  scrubTextString,
  scrubJwtToken,
  serializeVault,
  deserializeVault,
  saveVaultToFile,
  loadVaultFromFile,
  restoreFromVault
};

export type {
  Finding,
  InputFormat,
  PlainVaultFile,
  ScrubCategory,
  ScrubOptions,
  ScrubResult,
  ScrubStats,
  VaultFile
};
