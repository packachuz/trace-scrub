import type { ScrubEngine } from '../core/engine.js';
import {
  scrubCookieHeaderString,
  scrubSetCookieHeaderString,
  scrubUrlString
} from './har.js';

export function scrubTextString(input: string, engine: ScrubEngine): string {
  let output = input;

  // 1. Scrub HTTP / cURL Authorization headers: Authorization: Bearer ... or Authorization: Basic ...
  output = output.replace(
    /^(\s*(?:-\w|--header)?\s*["']?(?:Authorization|Proxy-Authorization)\s*:\s*)([^"'\r\n]+)(["']?)/gim,
    (_m, prefix: string, val: string, suffix: string) => {
      return `${prefix}${engine.scrubAuthorizationHeader(val.trim(), 'text.header.Authorization')}${suffix}`;
    }
  );

  // 2. Scrub HTTP / cURL Cookie headers
  output = output.replace(
    /^(\s*(?:-\w|--header)?\s*["']?Cookie\s*:\s*)([^"'\r\n]+)(["']?)/gim,
    (_m, prefix: string, val: string, suffix: string) => {
      return `${prefix}${scrubCookieHeaderString(val, engine, 'text.header.Cookie')}${suffix}`;
    }
  );

  // 3. Scrub HTTP Set-Cookie headers
  output = output.replace(
    /^(\s*Set-Cookie\s*:\s*)([^\r\n]+)/gim,
    (_m, prefix: string, val: string) => {
      return `${prefix}${scrubSetCookieHeaderString(val, engine, 'text.header.Set-Cookie')}`;
    }
  );

  // 4. Scrub cURL -u / --user user:pass flags
  output = output.replace(
    /((?:^|\s)(?:-u|--user)\s+["']?)([^"'\s:]+):([^"'\s]+)(["']?)/g,
    (_m, prefix: string, user: string, pass: string, suffix: string) => {
      const sUser = engine.scrubSecretValue(user, 'secret', 'text.curl.user', 'user');
      const sPass = engine.scrubSecretValue(pass, 'password', 'text.curl.password', 'pass');
      return `${prefix}${sUser}:${sPass}${suffix}`;
    }
  );

  // 5. Scrub explicit URLs (https://... or http://...)
  output = output.replace(
    /\bhttps?:\/\/[^\s"'<>\\]+/gi,
    (urlMatch) => scrubUrlString(urlMatch, engine, 'text.url')
  );

  // 6. Scrub key=value or key: "value" secret assignments in logs/commands
  output = output.replace(
    /\b(password|passwd|secret|client_secret|api_key|apikey|access_token|refresh_token|x-api-key)(\s*[:=]\s*["']?)([^"'\s,&;}\]]+)(["']?)/gi,
    (_m, key: string, sep: string, val: string, suffix: string) => {
      const cat = /password|passwd/i.test(key)
        ? 'password'
        : /api/i.test(key)
          ? 'api_key'
          : 'secret';
      const scrubbed = engine.scrubSecretValue(val, cat, `text.${key}`, key.toLowerCase());
      return `${key}${sep}${scrubbed}${suffix}`;
    }
  );

  // 7. Run general inline scrubber (connection URIs, JWTs, known API keys, emails, IPs, UUIDs)
  output = engine.scrubInlineString(output, 'text');

  return output;
}
