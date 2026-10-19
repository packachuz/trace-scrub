export type ScrubCategory =
  | 'jwt'
  | 'api_key'
  | 'authorization'
  | 'cookie'
  | 'password'
  | 'secret'
  | 'connection_uri'
  | 'email'
  | 'ipv4'
  | 'ipv6'
  | 'hostname'
  | 'uuid'
  | 'high_entropy';

export type InputFormat = 'auto' | 'har' | 'json' | 'jsonl' | 'env' | 'text';

export interface Finding {
  category: ScrubCategory;
  location: string;
  originalPreview: string;
  replacement: string;
  count: number;
}

export interface ScrubOptions {
  /** Optional hex or string salt for deterministic pseudonymization across runs */
  salt?: string;
  /** Keep public/custom hostnames untouched (default: false — scrubs hostnames while grouping by base domain) */
  keepHostnames?: boolean;
  /** Scrub UUIDv4 identifiers (default: true) */
  scrubUuids?: boolean;
  /** Additional custom sensitive key names */
  extraSensitiveKeys?: string[];
  /** Custom values or regex patterns to allowlist */
  allowlist?: string[];
}

export interface ScrubStats {
  totalReplacements: number;
  uniqueSecretsScrubbed: number;
  byCategory: Partial<Record<ScrubCategory, number>>;
}

export interface ScrubResult {
  output: string;
  format: Exclude<InputFormat, 'auto'>;
  findings: Finding[];
  stats: ScrubStats;
}

export interface PlainVaultFile {
  version: 1;
  encrypted: false;
  createdAt: string;
  saltHex: string;
  mappings: Record<string, string>; // pseudonym -> original
  categories: Record<string, ScrubCategory>;
}

export interface EncryptedVaultFile {
  version: 1;
  encrypted: true;
  createdAt: string;
  kdf: 'scrypt';
  kdfSaltHex: string;
  ivHex: string;
  authTagHex: string;
  ciphertextHex: string;
}

export type VaultFile = PlainVaultFile | EncryptedVaultFile;
