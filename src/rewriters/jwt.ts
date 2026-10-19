import type { ScrubEngine } from '../core/engine.js';

const JWT_IDENTITY_CLAIMS = new Set([
  'sub',
  'name',
  'given_name',
  'family_name',
  'middle_name',
  'nickname',
  'preferred_username',
  'upn',
  'jti',
  'client_id',
  'azp',
  'org_id',
  'tenant_id',
  'sid',
  'session_state',
  'phone_number'
]);

const JWT_PRESERVED_CLAIMS = new Set([
  'exp',
  'iat',
  'nbf',
  'auth_time',
  'alg',
  'typ',
  'scope',
  'scp',
  'roles',
  'permissions',
  'amr',
  'acr'
]);

function scrubJwtClaimValue(
  key: string,
  value: unknown,
  engine: ScrubEngine,
  location: string
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  const lowerKey = key.toLowerCase();
  if (JWT_PRESERVED_CLAIMS.has(lowerKey)) {
    return value;
  }

  if (typeof value === 'string') {
    if (lowerKey === 'email' || value.includes('@')) {
      return engine.scrubEmail(value, `${location}.${key}`);
    }
    if (lowerKey === 'iss' || lowerKey === 'aud') {
      try {
        const u = new URL(value);
        u.hostname = engine.scrubHostname(u.hostname, `${location}.${key}`);
        return u.toString();
      } catch {
        return engine.scrubInlineString(value, `${location}.${key}`);
      }
    }
    if (lowerKey === 'ipaddr' || lowerKey === 'ip') {
      return engine.scrubIpv4(value, `${location}.${key}`);
    }
    if (JWT_IDENTITY_CLAIMS.has(lowerKey)) {
      return engine.scrubSecretValue(value, 'jwt', `${location}.${key}`, lowerKey);
    }
    return engine.scrubInlineString(value, `${location}.${key}`);
  }

  if (Array.isArray(value)) {
    return value.map((item, idx) =>
      scrubJwtClaimValue(`${key}[${idx}]`, item, engine, location)
    );
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubJwtClaimValue(k, v, engine, `${location}.${key}`);
    }
    return out;
  }

  return value;
}

export function scrubJwtToken(
  token: string,
  engine: ScrubEngine,
  location = 'jwt'
): string {
  const clean = token.trim();
  if (engine.isAllowlisted(clean)) return token;

  const existing = engine.getExistingMapping(clean, 'jwt');
  if (existing) return existing;

  const parts = clean.split('.');
  if (parts.length !== 3) {
    return engine.scrubSecretValue(clean, 'jwt', location, 'jwt');
  }

  try {
    const headerJson = Buffer.from(parts[0]!, 'base64url').toString('utf8');
    const payloadJson = Buffer.from(parts[1]!, 'base64url').toString('utf8');

    const headerObj = JSON.parse(headerJson) as Record<string, unknown>;
    const payloadObj = JSON.parse(payloadJson) as Record<string, unknown>;

    const scrubbedHeader: Record<string, unknown> = { ...headerObj };
    if (typeof scrubbedHeader.kid === 'string') {
      scrubbedHeader.kid = engine.scrubSecretValue(
        scrubbedHeader.kid,
        'jwt',
        `${location}.header.kid`,
        'kid'
      );
    }

    const scrubbedPayload: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(payloadObj)) {
      scrubbedPayload[k] = scrubJwtClaimValue(k, v, engine, `${location}.payload`);
    }

    const newHeaderB64 = Buffer.from(JSON.stringify(scrubbedHeader), 'utf8').toString(
      'base64url'
    );
    const newPayloadB64 = Buffer.from(JSON.stringify(scrubbedPayload), 'utf8').toString(
      'base64url'
    );
    const dummySigB64 = engine.hmacBase64Url(`${newHeaderB64}.${newPayloadB64}`, 32);

    const pseudoJwt = `${newHeaderB64}.${newPayloadB64}.${dummySigB64}`;
    return engine.registerMapping(clean, pseudoJwt, 'jwt', location);
  } catch {
    return engine.scrubSecretValue(clean, 'jwt', location, 'jwt');
  }
}
