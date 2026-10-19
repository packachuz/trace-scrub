import crypto from 'node:crypto';
import {
  classifyIpv4,
  CONNECTION_URI_REGEX,
  EMAIL_INLINE_REGEX,
  extractRegistrableDomain,
  IPV4_INLINE_REGEX,
  IPV6_INLINE_REGEX,
  isLoopbackHostname,
  isLoopbackOrSpecialIpv4,
  JWT_EXACT_REGEX,
  JWT_INLINE_REGEX,
  KNOWN_TOKEN_PREFIXES,
  looksLikeHighEntropySecret,
  previewValue,
  UUID_INLINE_REGEX
} from './detectors.js';
import type {
  Finding,
  PlainVaultFile,
  ScrubCategory,
  ScrubOptions,
  ScrubStats
} from './types.js';
import { scrubJwtToken } from '../rewriters/jwt.js';

export class ScrubEngine {
  public readonly salt: Buffer;
  public readonly options: Required<ScrubOptions>;

  private readonly forwardMap = new Map<string, string>(); // category:original -> pseudonym
  private readonly reverseMap = new Map<string, string>(); // pseudonym -> original
  private readonly categoryMap = new Map<string, ScrubCategory>(); // pseudonym -> category
  private readonly counters = new Map<string, number>();
  private readonly baseDomainMap = new Map<string, string>(); // corp.internal -> domain-01.example
  private readonly findingMap = new Map<string, Finding>(); // pseudonym -> Finding

  constructor(options: ScrubOptions = {}) {
    this.salt = options.salt
      ? crypto.createHash('sha256').update(options.salt).digest()
      : crypto.randomBytes(32);

    this.options = {
      salt: this.salt.toString('hex'),
      keepHostnames: options.keepHostnames ?? false,
      scrubUuids: options.scrubUuids ?? true,
      extraSensitiveKeys: options.extraSensitiveKeys ?? [],
      allowlist: options.allowlist ?? []
    };
  }

  public isAllowlisted(value: string): boolean {
    if (!value) return true;
    return this.options.allowlist.includes(value);
  }

  public hmacHex(value: string, length = 12): string {
    return crypto
      .createHmac('sha256', this.salt)
      .update(value)
      .digest('hex')
      .slice(0, length);
  }

  public hmacBase64Url(value: string, byteLength = 32): string {
    return crypto
      .createHmac('sha256', this.salt)
      .update(value)
      .digest()
      .subarray(0, byteLength)
      .toString('base64url');
  }

  private nextCounter(namespace: string): number {
    const current = (this.counters.get(namespace) ?? 0) + 1;
    this.counters.set(namespace, current);
    return current;
  }

  private padIndex(idx: number): string {
    return idx < 10 ? `0${idx}` : `${idx}`;
  }

  public registerMapping(
    original: string,
    pseudonym: string,
    category: ScrubCategory,
    location: string
  ): string {
    const key = `${category}:${original}`;
    this.forwardMap.set(key, pseudonym);
    this.reverseMap.set(pseudonym, original);
    this.categoryMap.set(pseudonym, category);

    const existing = this.findingMap.get(pseudonym);
    if (existing) {
      existing.count += 1;
    } else {
      this.findingMap.set(pseudonym, {
        category,
        location,
        originalPreview: previewValue(original),
        replacement: pseudonym,
        count: 1
      });
    }
    return pseudonym;
  }

  public getExistingMapping(original: string, category: ScrubCategory): string | undefined {
    const key = `${category}:${original}`;
    const existing = this.forwardMap.get(key);
    if (existing) {
      const f = this.findingMap.get(existing);
      if (f) f.count += 1;
    }
    return existing;
  }

  public scrubBaseDomain(baseDomain: string, location: string): string {
    const clean = baseDomain.toLowerCase().replace(/\.$/, '');
    if (isLoopbackHostname(clean)) return clean;

    const existing = this.baseDomainMap.get(clean);
    if (existing) return existing;

    const idx = this. padIndex(this.nextCounter('domain'));
    const pseudoDomain = `domain-${idx}.example`;
    this.baseDomainMap.set(clean, pseudoDomain);
    this.reverseMap.set(pseudoDomain, clean);
    this.categoryMap.set(pseudoDomain, 'hostname');
    this.findingMap.set(pseudoDomain, {
      category: 'hostname',
      location,
      originalPreview: previewValue(clean),
      replacement: pseudoDomain,
      count: 1
    });
    return pseudoDomain;
  }

  public scrubHostname(hostname: string, location = 'hostname'): string {
    const clean = hostname.trim().toLowerCase().replace(/\.$/, '');
    if (!clean || this.isAllowlisted(clean) || isLoopbackHostname(clean)) {
      return hostname;
    }
    if (this.options.keepHostnames) {
      return hostname;
    }
    // Check if it's actually an IPv4 address
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(clean)) {
      return this.scrubIpv4(clean, location);
    }

    const existing = this.getExistingMapping(clean, 'hostname');
    if (existing) return existing;

    const { subdomain, baseDomain } = extractRegistrableDomain(clean);
    const pseudoBase = this.scrubBaseDomain(baseDomain, location);

    if (!subdomain) {
      return this.registerMapping(clean, pseudoBase, 'hostname', location);
    }

    const idx = this.padIndex(this.nextCounter(`host:${pseudoBase}`));
    const pseudoHost = `host-${idx}.${pseudoBase}`;
    return this.registerMapping(clean, pseudoHost, 'hostname', location);
  }

  public scrubEmail(email: string, location = 'email'): string {
    const clean = email.trim();
    if (this.isAllowlisted(clean)) return email;
    if (clean.toLowerCase().endsWith('.example') || clean.toLowerCase().endsWith('@example.com')) {
      return email;
    }

    const existing = this.getExistingMapping(clean, 'email');
    if (existing) return existing;

    const atIdx = clean.lastIndexOf('@');
    if (atIdx === -1) return email;

    const domainPart = clean.slice(atIdx + 1).toLowerCase();
    const { baseDomain } = extractRegistrableDomain(domainPart);
    const pseudoDomain = this.scrubBaseDomain(baseDomain, location);

    const idx = this.padIndex(this.nextCounter(`user:${pseudoDomain}`));
    const pseudoEmail = `user-${idx}@${pseudoDomain}`;
    return this.registerMapping(clean, pseudoEmail, 'email', location);
  }

  public scrubIpv4(ip: string, location = 'ipv4'): string {
    const clean = ip.trim();
    if (this.isAllowlisted(clean) || isLoopbackOrSpecialIpv4(clean)) {
      return ip;
    }

    const existing = this.getExistingMapping(clean, 'ipv4');
    if (existing) return existing;

    const kind = classifyIpv4(clean);
    let prefix = '203.0.113'; // RFC 5737 TEST-NET-3 (public)
    if (kind === 'private_10') {
      prefix = '192.0.2'; // RFC 5737 TEST-NET-1 (10.x)
    } else if (kind === 'private_other') {
      prefix = '198.51.100'; // RFC 5737 TEST-NET-2 (172.16/192.168)
    }

    const hostNum = ((this.nextCounter(`ipv4:${prefix}`) - 1) % 253) + 1;
    const pseudoIp = `${prefix}.${hostNum}`;
    return this.registerMapping(clean, pseudoIp, 'ipv4', location);
  }

  public scrubIpv6(ip: string, location = 'ipv6'): string {
    const clean = ip.trim();
    const lower = clean.toLowerCase();
    if (
      this.isAllowlisted(clean) ||
      lower === '::1' ||
      lower === '::' ||
      lower.startsWith('2001:db8:') ||
      lower.startsWith('fe80::1')
    ) {
      return ip;
    }

    const existing = this.getExistingMapping(clean, 'ipv6');
    if (existing) return existing;

    const idx = this.nextCounter('ipv6').toString(16);
    const pseudoIp = `2001:db8::${idx}`;
    return this.registerMapping(clean, pseudoIp, 'ipv6', location);
  }

  public scrubUuid(uuid: string, location = 'uuid'): string {
    const clean = uuid.trim();
    if (!this.options.scrubUuids || this.isAllowlisted(clean)) {
      return uuid;
    }
    // Already scrubbed deterministic UUID prefix (00000000-0000-4000-8000-...)
    if (clean.startsWith('00000000-0000-4000-8')) {
      return uuid;
    }

    const existing = this.getExistingMapping(clean, 'uuid');
    if (existing) return existing;

    const idx = this.nextCounter('uuid');
    const tail = idx.toString(16).padStart(12, '0');
    const hashMid = this.hmacHex(clean, 3);
    const pseudoUuid = `00000000-0000-4000-8${hashMid}-${tail}`;
    return this.registerMapping(clean, pseudoUuid, 'uuid', location);
  }

  public scrubSecretValue(
    value: string,
    category: ScrubCategory,
    location: string,
    customPrefix?: string
  ): string {
    const clean = value.trim();
    if (!clean || this.isAllowlisted(clean)) return value;

    // Check if the value is a JWT
    if (JWT_EXACT_REGEX.test(clean)) {
      return scrubJwtToken(clean, this, location);
    }

    // Check if the value matches a known token prefix
    for (const rule of KNOWN_TOKEN_PREFIXES) {
      if (clean.startsWith(rule.prefix)) {
        const existing = this.getExistingMapping(clean, 'api_key');
        if (existing) return existing;
        const idx = this.padIndex(this.nextCounter('api_key'));
        const digest = this.hmacHex(clean, 12);
        const pseudo = `${rule.replacementPrefix}${idx}_${digest}`;
        return this.registerMapping(clean, pseudo, 'api_key', location);
      }
    }

    const existing = this.getExistingMapping(clean, category);
    if (existing) return existing;

    const idx = this.padIndex(this.nextCounter(category));
    const digest = this.hmacHex(clean, 10);
    const label = customPrefix ?? category;
    const pseudo = `${label}_scrub_${idx}_${digest}`;
    return this.registerMapping(clean, pseudo, category, location);
  }

  public scrubAuthorizationHeader(headerValue: string, location = 'header.Authorization'): string {
    const trimmed = headerValue.trim();
    if (!trimmed || this.isAllowlisted(trimmed)) return headerValue;

    const bearerMatch = /^Bearer\s+(.+)$/i.exec(trimmed);
    if (bearerMatch && bearerMatch[1]) {
      const token = bearerMatch[1].trim();
      if (JWT_EXACT_REGEX.test(token)) {
        return `Bearer ${scrubJwtToken(token, this, location)}`;
      }
      return `Bearer ${this.scrubSecretValue(token, 'authorization', location, 'bearer')}`;
    }

    const basicMatch = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(trimmed);
    if (basicMatch && basicMatch[1]) {
      const b64 = basicMatch[1];
      const existing = this.getExistingMapping(b64, 'authorization');
      if (existing) return `Basic ${existing}`;

      const idx = this.padIndex(this.nextCounter('basic_auth'));
      const dummyCreds = Buffer.from(`user-${idx}:password_scrub_${idx}_${this.hmacHex(b64, 8)}`).toString(
        'base64'
      );
      this.registerMapping(b64, dummyCreds, 'authorization', location);
      return `Basic ${dummyCreds}`;
    }

    return this.scrubSecretValue(trimmed, 'authorization', location, 'auth');
  }

  public scrubConnectionUri(uri: string, location = 'connection_uri'): string {
    return uri.replace(
      CONNECTION_URI_REGEX,
      (_full, scheme: string, user: string, pass: string, host: string, port?: string, pathPart?: string) => {
        const pseudoUser = user ? this.scrubSecretValue(user, 'secret', `${location}.user`, 'dbuser') : '';
        const pseudoPass = this.scrubSecretValue(pass, 'password', `${location}.password`, 'dbpass');
        const pseudoHost = this.scrubHostname(host, `${location}.host`);
        return `${scheme}${pseudoUser}:${pseudoPass}@${pseudoHost}${port ?? ''}${pathPart ?? ''}`;
      }
    );
  }

  public scrubInlineString(input: string, location = 'text'): string {
    if (!input || this.isAllowlisted(input)) return input;

    let result = input;

    // 1. Connection URIs (postgres://user:pass@host:5432/db)
    result = this.scrubConnectionUri(result, location);

    // 2. Inline JWTs
    result = result.replace(JWT_INLINE_REGEX, (match) => scrubJwtToken(match, this, location));

    // 3. Known API key prefixes (ghp_, sk-, AKIA, etc.)
    for (const rule of KNOWN_TOKEN_PREFIXES) {
      result = result.replace(rule.regex, (match) => {
        const existing = this.getExistingMapping(match, 'api_key');
        if (existing) return existing;
        const idx = this.padIndex(this.nextCounter('api_key'));
        const digest = this.hmacHex(match, 12);
        const pseudo = `${rule.replacementPrefix}${idx}_${digest}`;
        return this.registerMapping(match, pseudo, 'api_key', location);
      });
    }

    // 4. Emails
    result = result.replace(EMAIL_INLINE_REGEX, (match) => this.scrubEmail(match, location));

    // 5. IPv4 addresses
    result = result.replace(IPV4_INLINE_REGEX, (match) => this.scrubIpv4(match, location));

    // 6. IPv6 addresses
    result = result.replace(IPV6_INLINE_REGEX, (match) => this.scrubIpv6(match, location));

    // 7. UUIDs
    if (this.options.scrubUuids) {
      result = result.replace(UUID_INLINE_REGEX, (match) => this.scrubUuid(match, location));
    }

    // 8. If the entire string is a single token and looks like a high-entropy secret
    if (result === input && looksLikeHighEntropySecret(result)) {
      return this.scrubSecretValue(result, 'high_entropy', location, 'secret');
    }

    return result;
  }

  public getFindings(): Finding[] {
    return Array.from(this.findingMap.values());
  }

  public getStats(): ScrubStats {
    const byCategory: Partial<Record<ScrubCategory, number>> = {};
    let totalReplacements = 0;

    for (const f of this.findingMap.values()) {
      totalReplacements += f.count;
      byCategory[f.category] = (byCategory[f.category] ?? 0) + f.count;
    }

    return {
      totalReplacements,
      uniqueSecretsScrubbed: this.findingMap.size,
      byCategory
    };
  }

  public exportVault(): PlainVaultFile {
    const mappings: Record<string, string> = {};
    const categories: Record<string, ScrubCategory> = {};

    for (const [pseudo, original] of this.reverseMap.entries()) {
      mappings[pseudo] = original;
    }
    for (const [pseudo, cat] of this.categoryMap.entries()) {
      categories[pseudo] = cat;
    }

    return {
      version: 1,
      encrypted: false,
      createdAt: new Date().toISOString(),
      saltHex: this.salt.toString('hex'),
      mappings,
      categories
    };
  }
}
