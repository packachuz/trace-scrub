import crypto from 'node:crypto';
import fs from 'node:fs';
import type { EncryptedVaultFile, PlainVaultFile, VaultFile } from './types.js';

export function serializeVault(vault: PlainVaultFile, passphrase?: string): string {
  if (!passphrase) {
    return JSON.stringify(vault, null, 2);
  }

  const kdfSalt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, kdfSalt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const plaintext = Buffer.from(JSON.stringify(vault), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const envelope: EncryptedVaultFile = {
    version: 1,
    encrypted: true,
    createdAt: vault.createdAt,
    kdf: 'scrypt',
    kdfSaltHex: kdfSalt.toString('hex'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    ciphertextHex: encrypted.toString('hex')
  };

  return JSON.stringify(envelope, null, 2);
}

export function deserializeVault(rawJson: string, passphrase?: string): PlainVaultFile {
  const parsed = JSON.parse(rawJson) as VaultFile;
  if (!parsed || parsed.version !== 1) {
    throw new Error('Invalid or unsupported trace-scrub vault file format.');
  }

  if (!parsed.encrypted) {
    return parsed;
  }

  if (!passphrase) {
    throw new Error(
      'This vault file is encrypted with AES-256-GCM. Please provide --passphrase to decrypt it.'
    );
  }

  const kdfSalt = Buffer.from(parsed.kdfSaltHex, 'hex');
  const iv = Buffer.from(parsed.ivHex, 'hex');
  const authTag = Buffer.from(parsed.authTagHex, 'hex');
  const ciphertext = Buffer.from(parsed.ciphertextHex, 'hex');

  const key = crypto.scryptSync(passphrase, kdfSalt, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8')) as PlainVaultFile;
  } catch {
    throw new Error('Failed to decrypt vault file: invalid passphrase or tampered ciphertext.');
  }
}

export function saveVaultToFile(
  filePath: string,
  vault: PlainVaultFile,
  passphrase?: string
): void {
  const content = serializeVault(vault, passphrase);
  fs.writeFileSync(filePath, content, { encoding: 'utf8', mode: 0o600 });
}

export function loadVaultFromFile(filePath: string, passphrase?: string): PlainVaultFile {
  const raw = fs.readFileSync(filePath, 'utf8');
  return deserializeVault(raw, passphrase);
}

export function restoreFromVault(scrubbedText: string, vault: PlainVaultFile): string {
  // Sort pseudonyms longest-first so full JWTs or full subdomains are replaced before shorter base domains
  const entries = Object.entries(vault.mappings).sort(
    ([a], [b]) => b.length - a.length
  );

  let output = scrubbedText;
  for (const [pseudonym, original] of entries) {
    if (!pseudonym || !output.includes(pseudonym)) continue;
    output = output.split(pseudonym).join(original);
  }
  return output;
}
