export interface TokenPrefixRule {
  name: string;
  prefix: string;
  regex: RegExp;
  replacementPrefix: string;
}

export const KNOWN_TOKEN_PREFIXES: TokenPrefixRule[] = [
  {
    name: 'GitHub Fine-Grained PAT',
    prefix: 'github_pat_',
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
    replacementPrefix: 'github_pat_scrub_'
  },
  {
    name: 'GitHub Personal Access Token',
    prefix: 'ghp_',
    regex: /\bghp_[A-Za-z0-9]{20,255}\b/g,
    replacementPrefix: 'ghp_scrub_'
  },
  {
    name: 'GitHub OAuth Token',
    prefix: 'gho_',
    regex: /\bgho_[A-Za-z0-9]{20,255}\b/g,
    replacementPrefix: 'gho_scrub_'
  },
  {
    name: 'GitHub User/Server Token',
    prefix: 'ghu_',
    regex: /\bgh[us]_[A-Za-z0-9]{20,255}\b/g,
    replacementPrefix: 'ghu_scrub_'
  },
  {
    name: 'OpenAI Project Key',
    prefix: 'sk-proj-',
    regex: /\bsk-proj-[A-Za-z0-9_-]{16,255}\b/g,
    replacementPrefix: 'sk-proj-scrub-'
  },
  {
    name: 'OpenAI / Stripe / Secret Key',
    prefix: 'sk-',
    regex: /\bsk-(?:live-|test-)?[A-Za-z0-9]{16,255}\b/g,
    replacementPrefix: 'sk-scrub-'
  },
  {
    name: 'Anthropic API Key',
    prefix: 'sk-ant-',
    regex: /\bsk-ant-[A-Za-z0-9_-]{16,255}\b/g,
    replacementPrefix: 'sk-ant-scrub-'
  },
  {
    name: 'AWS Access Key ID',
    prefix: 'AKIA',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    replacementPrefix: 'AKIA_SCRUB_'
  },
  {
    name: 'Slack Token',
    prefix: 'xox',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g,
    replacementPrefix: 'xoxb-scrub-'
  },
  {
    name: 'Google API Key',
    prefix: 'AIza',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    replacementPrefix: 'AIza_scrub_'
  },
  {
    name: 'GitLab PAT',
    prefix: 'glpat-',
    regex: /\bglpat-[A-Za-z0-9_-]{16,255}\b/g,
    replacementPrefix: 'glpat-scrub-'
  },
  {
    name: 'npm Access Token',
    prefix: 'npm_',
    regex: /\bnpm_[A-Za-z0-9]{20,255}\b/g,
    replacementPrefix: 'npm_scrub_'
  }
];

export const JWT_EXACT_REGEX =
  /^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{4,}$/;

export const JWT_INLINE_REGEX =
  /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{4,}\b/g;

export const EMAIL_INLINE_REGEX =
  /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b/g;

export const UUID_INLINE_REGEX =
  /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b/g;

export const IPV4_INLINE_REGEX =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

export const IPV6_INLINE_REGEX =
  /\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b/g;

export const CONNECTION_URI_REGEX =
  /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^:@\s/"']+):([^@\s/"']+)@([^\s/"':]+)(:\d+)?(\/[^\s"']*)?/g;

const SENSITIVE_KEY_PATTERNS = [
  /^authorization$/i,
  /^proxy-authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^x-api-key$/i,
  /^x-auth-token$/i,
  /^x-csrf-token$/i,
  /^x-xsrf-token$/i,
  /^x-amz-security-token$/i,
  /^api[-_]?key$/i,
  /^client[-_]?secret$/i,
  /^access[-_]?token$/i,
  /^refresh[-_]?token$/i,
  /^id[-_]?token$/i,
  /^auth[-_]?token$/i,
  /^session[-_]?token$/i,
  /^session[-_]?id$/i,
  /^sid$/i,
  /^csrf[-_]?token$/i,
  /^private[-_]?key$/i,
  /^secret[-_]?key$/i,
  /^secret$/i,
  /^password$/i,
  /^passwd$/i,
  /^pwd$/i,
  /^passphrase$/i,
  /^bearer$/i,
  /^token$/i,
  /^credential$/i,
  /^credentials$/i,
  /^connection[-_]?string$/i,
  /^database[-_]?url$/i,
  /^redis[-_]?url$/i,
  /^webhook[-_]?secret$/i,
  /^signing[-_]?secret$/i
];

const PUBLIC_SAFE_KEYS = new Set([
  'port',
  'node_env',
  'env',
  'environment',
  'log_level',
  'debug',
  'tz',
  'timezone',
  'lang',
  'locale',
  'timeout',
  'max_retries',
  'retry_count',
  'version',
  'app_name',
  'service_name',
  'region',
  'method',
  'status',
  'status_code',
  'statuscode',
  'httpversion',
  'Content-Type',
  'content-type',
  'accept',
  'accept-encoding',
  'accept-language',
  'user-agent',
  'cache-control',
  'connection',
  'content-length',
  'transfer-encoding',
  'vary'
]);

export function isSensitiveKeyName(
  key: string,
  extraKeys: string[] = []
): 'password' | 'cookie' | 'authorization' | 'api_key' | 'secret' | null {
  const normalized = key.trim();
  if (PUBLIC_SAFE_KEYS.has(normalized.toLowerCase())) {
    return null;
  }
  const lower = normalized.toLowerCase();
  if (extraKeys.some((k) => k.toLowerCase() === lower)) {
    return 'secret';
  }
  if (/^(authorization|proxy-authorization|bearer)$/i.test(normalized)) {
    return 'authorization';
  }
  if (/^(cookie|set-cookie)$/i.test(normalized)) {
    return 'cookie';
  }
  if (/(password|passwd|pwd|passphrase)/i.test(normalized)) {
    return 'password';
  }
  if (/(api[-_]?key|x-api-key)/i.test(normalized)) {
    return 'api_key';
  }
  for (const pat of SENSITIVE_KEY_PATTERNS) {
    if (pat.test(normalized)) {
      return 'secret';
    }
  }
  if (/(?:_secret|_token|_key|_password|_passwd|secret_|token_)/i.test(normalized)) {
    return 'secret';
  }
  return null;
}

export function isLoopbackOrSpecialIpv4(ip: string): boolean {
  if (
    ip === '127.0.0.1' ||
    ip === '0.0.0.0' ||
    ip === '255.255.255.255' ||
    ip.startsWith('127.') ||
    ip.startsWith('192.0.2.') ||
    ip.startsWith('198.51.100.') ||
    ip.startsWith('203.0.113.')
  ) {
    return true;
  }
  return false;
}

export function classifyIpv4(ip: string): 'loopback' | 'private_10' | 'private_other' | 'public' {
  if (isLoopbackOrSpecialIpv4(ip)) {
    return 'loopback';
  }
  const parts = ip.split('.').map(Number);
  const a = parts[0] ?? 0;
  const b = parts[1] ?? 0;
  if (a === 10) {
    return 'private_10';
  }
  if (
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  ) {
    return 'private_other';
  }
  return 'public';
}

export function isLoopbackHostname(host: string): boolean {
  const lower = host.toLowerCase();
  return (
    lower === 'localhost' ||
    lower.endsWith('.example.com') ||
    lower.endsWith('.example.org') ||
    lower.endsWith('.example.net') ||
    lower.endsWith('.example')
  );
}

export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function looksLikeHighEntropySecret(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 20 || trimmed.length > 512) return false;
  // Must not contain spaces, newlines, or look like a URL path or regular sentence
  if (/[\s/]/.test(trimmed)) return false;
  if (/^[0-9]+$/.test(trimmed)) return false;
  if (/^[a-zA-Z]+$/.test(trimmed)) return false;
  // Must mix character classes (e.g. upper + lower + digits)
  const hasLower = /[a-z]/.test(trimmed);
  const hasUpper = /[A-Z]/.test(trimmed);
  const hasDigit = /[0-9]/.test(trimmed);
  if (!((hasLower && hasUpper && hasDigit) || (hasLower && hasDigit && trimmed.length >= 32))) {
    return false;
  }
  return shannonEntropy(trimmed) >= 4.1;
}

export function extractRegistrableDomain(hostOrDomain: string): {
  subdomain: string;
  baseDomain: string;
} {
  const clean = hostOrDomain.toLowerCase().replace(/\.$/, '');
  const parts = clean.split('.');
  if (parts.length <= 2) {
    return { subdomain: '', baseDomain: clean };
  }
  const baseDomain = parts.slice(-2).join('.');
  const subdomain = parts.slice(0, -2).join('.');
  return { subdomain, baseDomain };
}

export function previewValue(val: string): string {
  if (val.length <= 8) {
    return val.slice(0, 2) + '***';
  }
  return `${val.slice(0, 4)}...${val.slice(-3)} (${val.length} chars)`;
}
