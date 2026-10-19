import { isSensitiveKeyName } from '../core/detectors.js';
import type { ScrubEngine } from '../core/engine.js';

export function scrubJsonValue(
  value: unknown,
  engine: ScrubEngine,
  path = 'root',
  parentKey?: string
): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'boolean' || typeof value === 'number') {
    return value;
  }

  if (typeof value === 'string') {
    if (parentKey) {
      const sensitiveKind = isSensitiveKeyName(
        parentKey,
        engine.options.extraSensitiveKeys
      );
      if (sensitiveKind === 'authorization') {
        return engine.scrubAuthorizationHeader(value, path);
      }
      if (sensitiveKind) {
        return engine.scrubSecretValue(value, sensitiveKind, path, parentKey.toLowerCase());
      }
      if (/^(email|user_email|customer_email|recipient)$/i.test(parentKey) && value.includes('@')) {
        return engine.scrubEmail(value, path);
      }
      if (/^(ip|ip_address|client_ip|remote_addr|server_ip|host_ip)$/i.test(parentKey)) {
        return engine.scrubInlineString(value, path);
      }
      if (/^(host|hostname|domain|server_name)$/i.test(parentKey)) {
        return engine.scrubHostname(value, path);
      }
    }

    return engine.scrubInlineString(value, path);
  }

  if (Array.isArray(value)) {
    return value.map((item, idx) =>
      scrubJsonValue(item, engine, `${path}[${idx}]`, parentKey)
    );
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = scrubJsonValue(v, engine, `${path}.${k}`, k);
    }
    return result;
  }

  return value;
}

export function scrubJsonString(input: string, engine: ScrubEngine, indent = 2): string {
  const parsed = JSON.parse(input) as unknown;
  const scrubbed = scrubJsonValue(parsed, engine, 'json');
  return JSON.stringify(scrubbed, null, indent);
}

export function scrubJsonlString(input: string, engine: ScrubEngine): string {
  const lines = input.split(/\r?\n/);
  const lineBreak = input.includes('\r\n') ? '\r\n' : '\n';

  return lines
    .map((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      try {
        const parsed = JSON.parse(trimmed) as unknown;
        const scrubbed = scrubJsonValue(parsed, engine, `jsonl[${idx}]`);
        return JSON.stringify(scrubbed);
      } catch {
        return engine.scrubInlineString(line, `jsonl[${idx}]`);
      }
    })
    .join(lineBreak);
}
