import { isSensitiveKeyName } from '../core/detectors.js';
import type { ScrubEngine } from '../core/engine.js';
import { scrubJsonValue } from './json.js';

interface HarNameValue {
  name: string;
  value: string;
  [key: string]: unknown;
}

interface HarCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  [key: string]: unknown;
}

const SET_COOKIE_ATTRIBUTES = new Set([
  'path',
  'domain',
  'expires',
  'max-age',
  'samesite',
  'secure',
  'httponly',
  'partitioned',
  'priority'
]);

export function scrubCookieHeaderString(
  cookieHeader: string,
  engine: ScrubEngine,
  location: string
): string {
  return cookieHeader
    .split(';')
    .map((pair) => {
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) return pair;
      const rawName = pair.slice(0, eqIdx);
      const rawVal = pair.slice(eqIdx + 1);
      const trimmedName = rawName.trim();
      const scrubbedVal = engine.scrubSecretValue(
        rawVal.trim(),
        'cookie',
        `${location}.${trimmedName}`,
        'cookie'
      );
      return `${rawName}=${scrubbedVal}`;
    })
    .join(';');
}

export function scrubSetCookieHeaderString(
  setCookieHeader: string,
  engine: ScrubEngine,
  location: string
): string {
  const segments = setCookieHeader.split(';');
  return segments
    .map((seg, idx) => {
      const eqIdx = seg.indexOf('=');
      if (eqIdx === -1) return seg;
      const rawKey = seg.slice(0, eqIdx);
      const rawVal = seg.slice(eqIdx + 1);
      const cleanKey = rawKey.trim().toLowerCase();

      if (idx === 0) {
        const scrubbedVal = engine.scrubSecretValue(
          rawVal.trim(),
          'cookie',
          `${location}.${rawKey.trim()}`,
          'cookie'
        );
        return `${rawKey}=${scrubbedVal}`;
      }

      if (cleanKey === 'domain') {
        const leadingDot = rawVal.trim().startsWith('.') ? '.' : '';
        const host = rawVal.trim().replace(/^\./, '');
        return `${rawKey}=${leadingDot}${engine.scrubHostname(host, `${location}.domain`)}`;
      }

      if (SET_COOKIE_ATTRIBUTES.has(cleanKey)) {
        return seg;
      }

      return `${rawKey}=${engine.scrubSecretValue(rawVal.trim(), 'cookie', `${location}.${cleanKey}`, 'cookie')}`;
    })
    .join(';');
}

export function scrubUrlString(
  rawUrl: string,
  engine: ScrubEngine,
  location: string
): string {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.username) {
      parsed.username = engine.scrubSecretValue(
        decodeURIComponent(parsed.username),
        'secret',
        `${location}.username`,
        'user'
      );
    }
    if (parsed.password) {
      parsed.password = engine.scrubSecretValue(
        decodeURIComponent(parsed.password),
        'password',
        `${location}.password`,
        'pass'
      );
    }
    if (parsed.hostname) {
      parsed.hostname = engine.scrubHostname(parsed.hostname, `${location}.host`);
    }

    // Scrub URL path segments that contain emails, IPs, UUIDs, or tokens
    parsed.pathname = parsed.pathname
      .split('/')
      .map((seg) => (seg ? engine.scrubInlineString(seg, `${location}.path`) : seg))
      .join('/');

    // Scrub query parameters
    for (const [k, v] of Array.from(parsed.searchParams.entries())) {
      const sensitiveKind = isSensitiveKeyName(k, engine.options.extraSensitiveKeys);
      if (sensitiveKind) {
        parsed.searchParams.set(
          k,
          engine.scrubSecretValue(v, sensitiveKind, `${location}.query.${k}`, k.toLowerCase())
        );
      } else {
        parsed.searchParams.set(k, engine.scrubInlineString(v, `${location}.query.${k}`));
      }
    }

    return parsed.toString();
  } catch {
    return engine.scrubInlineString(rawUrl, location);
  }
}

function scrubBodyPayload(
  text: string,
  mimeType: string | undefined,
  engine: ScrubEngine,
  location: string
): string {
  const trimmed = text.trim();
  if (!trimmed) return text;

  const isJsonLike =
    (mimeType && mimeType.toLowerCase().includes('json')) ||
    ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']')));

  if (isJsonLike) {
    try {
      const parsed = JSON.parse(text) as unknown;
      const scrubbed = scrubJsonValue(parsed, engine, location);
      return JSON.stringify(scrubbed);
    } catch {
      // Fallback to inline scrubbing if invalid JSON
    }
  }

  if (mimeType && mimeType.toLowerCase().includes('application/x-www-form-urlencoded')) {
    try {
      const params = new URLSearchParams(text);
      for (const [k, v] of Array.from(params.entries())) {
        const sensitiveKind = isSensitiveKeyName(k, engine.options.extraSensitiveKeys);
        if (sensitiveKind) {
          params.set(
            k,
            engine.scrubSecretValue(v, sensitiveKind, `${location}.${k}`, k.toLowerCase())
          );
        } else {
          params.set(k, engine.scrubInlineString(v, `${location}.${k}`));
        }
      }
      return params.toString();
    } catch {
      // Fallback to inline scrubbing
    }
  }

  return engine.scrubInlineString(text, location);
}

function scrubHeadersArray(
  headers: HarNameValue[] | undefined,
  engine: ScrubEngine,
  location: string
): void {
  if (!Array.isArray(headers)) return;

  for (const h of headers) {
    if (!h || typeof h.name !== 'string' || typeof h.value !== 'string') continue;
    const lower = h.name.toLowerCase();

    if (lower === 'authorization' || lower === 'proxy-authorization') {
      h.value = engine.scrubAuthorizationHeader(h.value, `${location}.${h.name}`);
    } else if (lower === 'cookie') {
      h.value = scrubCookieHeaderString(h.value, engine, `${location}.Cookie`);
    } else if (lower === 'set-cookie') {
      h.value = scrubSetCookieHeaderString(h.value, engine, `${location}.Set-Cookie`);
    } else if (lower === 'host' || lower === ':authority' || lower === 'x-forwarded-host') {
      const [hostPart, portPart] = h.value.split(':');
      if (hostPart) {
        const scrubbedHost = engine.scrubHostname(hostPart, `${location}.${h.name}`);
        h.value = portPart ? `${scrubbedHost}:${portPart}` : scrubbedHost;
      }
    } else if (
      lower === 'origin' ||
      lower === 'referer' ||
      lower === 'location'
    ) {
      h.value = scrubUrlString(h.value, engine, `${location}.${h.name}`);
    } else if (
      lower === 'x-forwarded-for' ||
      lower === 'x-real-ip' ||
      lower === 'cf-connecting-ip' ||
      lower === 'true-client-ip'
    ) {
      h.value = engine.scrubInlineString(h.value, `${location}.${h.name}`);
    } else {
      const sensitiveKind = isSensitiveKeyName(h.name, engine.options.extraSensitiveKeys);
      if (sensitiveKind) {
        h.value = engine.scrubSecretValue(
          h.value,
          sensitiveKind,
          `${location}.${h.name}`,
          lower.replace(/[^a-z0-9]/g, '_')
        );
      } else {
        h.value = engine.scrubInlineString(h.value, `${location}.${h.name}`);
      }
    }
  }
}

function scrubCookiesArray(
  cookies: HarCookie[] | undefined,
  engine: ScrubEngine,
  location: string
): void {
  if (!Array.isArray(cookies)) return;
  for (const c of cookies) {
    if (!c || typeof c.name !== 'string' || typeof c.value !== 'string') continue;
    c.value = engine.scrubSecretValue(c.value, 'cookie', `${location}.${c.name}`, 'cookie');
    if (typeof c.domain === 'string' && c.domain) {
      const leadingDot = c.domain.startsWith('.') ? '.' : '';
      const cleanDomain = c.domain.replace(/^\./, '');
      c.domain = `${leadingDot}${engine.scrubHostname(cleanDomain, `${location}.${c.name}.domain`)}`;
    }
  }
}

function scrubNameValueParams(
  params: HarNameValue[] | undefined,
  engine: ScrubEngine,
  location: string
): void {
  if (!Array.isArray(params)) return;
  for (const p of params) {
    if (!p || typeof p.name !== 'string' || typeof p.value !== 'string') continue;
    const sensitiveKind = isSensitiveKeyName(p.name, engine.options.extraSensitiveKeys);
    if (sensitiveKind) {
      p.value = engine.scrubSecretValue(
        p.value,
        sensitiveKind,
        `${location}.${p.name}`,
        p.name.toLowerCase()
      );
    } else {
      p.value = engine.scrubInlineString(p.value, `${location}.${p.name}`);
    }
  }
}

export function scrubHarObject(harRoot: Record<string, unknown>, engine: ScrubEngine): Record<string, unknown> {
  const clone = structuredClone(harRoot) as {
    log?: {
      entries?: Array<Record<string, unknown>>;
      pages?: Array<Record<string, unknown>>;
    };
  };

  if (!clone.log || !Array.isArray(clone.log.entries)) {
    return scrubJsonValue(clone, engine, 'har') as Record<string, unknown>;
  }

  clone.log.entries.forEach((entry, idx) => {
    const loc = `har.entries[${idx}]`;

    if (typeof entry.serverIPAddress === 'string' && entry.serverIPAddress) {
      entry.serverIPAddress = engine.scrubInlineString(
        entry.serverIPAddress,
        `${loc}.serverIPAddress`
      );
    }

    const req = entry.request as Record<string, unknown> | undefined;
    if (req) {
      if (typeof req.url === 'string') {
        req.url = scrubUrlString(req.url, engine, `${loc}.request.url`);
      }
      scrubHeadersArray(
        req.headers as HarNameValue[] | undefined,
        engine,
        `${loc}.request.headers`
      );
      scrubCookiesArray(
        req.cookies as HarCookie[] | undefined,
        engine,
        `${loc}.request.cookies`
      );
      scrubNameValueParams(
        req.queryString as HarNameValue[] | undefined,
        engine,
        `${loc}.request.queryString`
      );

      const postData = req.postData as Record<string, unknown> | undefined;
      if (postData) {
        const mimeType = typeof postData.mimeType === 'string' ? postData.mimeType : undefined;
        if (typeof postData.text === 'string' && postData.text) {
          const scrubbedPostText = scrubBodyPayload(
            postData.text,
            mimeType,
            engine,
            `${loc}.request.postData.text`
          );
          postData.text = scrubbedPostText;
          req.bodySize = Buffer.byteLength(scrubbedPostText, 'utf8');
        }
        scrubNameValueParams(
          postData.params as HarNameValue[] | undefined,
          engine,
          `${loc}.request.postData.params`
        );
      }
    }

    const res = entry.response as Record<string, unknown> | undefined;
    if (res) {
      if (typeof res.redirectURL === 'string' && res.redirectURL) {
        res.redirectURL = scrubUrlString(res.redirectURL, engine, `${loc}.response.redirectURL`);
      }
      scrubHeadersArray(
        res.headers as HarNameValue[] | undefined,
        engine,
        `${loc}.response.headers`
      );
      scrubCookiesArray(
        res.cookies as HarCookie[] | undefined,
        engine,
        `${loc}.response.cookies`
      );

      const content = res.content as Record<string, unknown> | undefined;
      if (content && typeof content.text === 'string' && content.text) {
        const mimeType = typeof content.mimeType === 'string' ? content.mimeType : undefined;
        if (content.encoding === 'base64') {
          try {
            const decoded = Buffer.from(content.text, 'base64').toString('utf8');
            const scrubbedDecoded = scrubBodyPayload(
              decoded,
              mimeType,
              engine,
              `${loc}.response.content.text`
            );
            content.text = Buffer.from(scrubbedDecoded, 'utf8').toString('base64');
            content.size = Buffer.byteLength(scrubbedDecoded, 'utf8');
          } catch {
            // Leave binary base64 payloads untouched
          }
        } else {
          const scrubbedContentText = scrubBodyPayload(
            content.text,
            mimeType,
            engine,
            `${loc}.response.content.text`
          );
          content.text = scrubbedContentText;
          content.size = Buffer.byteLength(scrubbedContentText, 'utf8');
        }
      }
    }
  });

  return clone as Record<string, unknown>;
}

export function scrubHarString(input: string, engine: ScrubEngine, indent = 2): string {
  const parsed = JSON.parse(input) as Record<string, unknown>;
  const scrubbed = scrubHarObject(parsed, engine);
  return JSON.stringify(scrubbed, null, indent);
}
