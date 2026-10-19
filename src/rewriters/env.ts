import { CONNECTION_URI_REGEX, isSensitiveKeyName } from '../core/detectors.js';
import type { ScrubEngine } from '../core/engine.js';

export function scrubEnvString(input: string, engine: ScrubEngine): string {
  const lines = input.split(/\r?\n/);
  const lineBreak = input.includes('\r\n') ? '\r\n' : '\n';

  return lines
    .map((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) {
        return line;
      }

      const match = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/.exec(line);
      if (!match) {
        return engine.scrubInlineString(line, `env[${idx + 1}]`);
      }

      const prefix = match[1] ?? '';
      const key = match[2] ?? '';
      const eq = match[3] ?? '=';
      const rawValuePart = match[4] ?? '';

      // Extract inline comment if unquoted
      let quoteChar = '';
      let innerValue = rawValuePart;
      let trailingComment = '';

      if (
        (rawValuePart.startsWith('"') && rawValuePart.endsWith('"')) ||
        (rawValuePart.startsWith("'") && rawValuePart.endsWith("'"))
      ) {
        quoteChar = rawValuePart[0]!;
        innerValue = rawValuePart.slice(1, -1);
      } else {
        const commentIdx = rawValuePart.indexOf(' #');
        if (commentIdx !== -1) {
          innerValue = rawValuePart.slice(0, commentIdx);
          trailingComment = rawValuePart.slice(commentIdx);
        }
      }

      const cleanVal = innerValue.trim();
      if (!cleanVal) {
        return line;
      }

      const loc = `env.${key}`;
      CONNECTION_URI_REGEX.lastIndex = 0;
      if (CONNECTION_URI_REGEX.test(cleanVal)) {
        CONNECTION_URI_REGEX.lastIndex = 0;
        const scrubbedUri = engine.scrubConnectionUri(cleanVal, loc);
        return `${prefix}${key}${eq}${quoteChar}${scrubbedUri}${quoteChar}${trailingComment}`;
      }

      const sensitiveKind = isSensitiveKeyName(key, engine.options.extraSensitiveKeys);
      if (sensitiveKind) {
        const scrubbedVal = engine.scrubSecretValue(
          cleanVal,
          sensitiveKind,
          loc,
          key.toLowerCase()
        );
        return `${prefix}${key}${eq}${quoteChar}${scrubbedVal}${quoteChar}${trailingComment}`;
      }

      const scrubbedInline = engine.scrubInlineString(cleanVal, loc);
      return `${prefix}${key}${eq}${quoteChar}${scrubbedInline}${quoteChar}${trailingComment}`;
    })
    .join(lineBreak);
}
