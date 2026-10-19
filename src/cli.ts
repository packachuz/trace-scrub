#!/usr/bin/env node
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import {
  loadVaultFromFile,
  restoreFromVault,
  saveVaultToFile,
  scrubTrace
} from './index.js';
import type { Finding, InputFormat, ScrubStats } from './core/types.js';

const HELP_TEXT = `
trace-scrub — Relational, Format-Preserving Network, HAR & Log Sanitizer

USAGE:
  trace-scrub <command> [input-file] [options]

COMMANDS:
  clean [file]     Sanitize a .har, .json, .jsonl, .env, or log/cURL file (reads stdin if no file)
  audit [file]     Dry-run scan reporting all detected secrets, tokens, IPs & PII without modifying files
  restore [file]   Restore original values in a scrubbed file or LLM response using a vault map

OPTIONS:
  -o, --output <file>         Write output to file instead of stdout (for clean/restore)
  -f, --format <fmt>          Input format: auto | har | json | jsonl | env | text (default: auto)
  -m, --map <file>            Path to save/load reversible mapping vault (.scrub-map.json)
  -p, --passphrase <secret>   Encrypt/decrypt the mapping vault with AES-256-GCM (scrypt KDF)
  -s, --salt <string>         Deterministic session salt for reproducible pseudonyms
      --keep-hostnames        Do not pseudonymize hostnames/domains
      --no-scrub-uuids        Do not pseudonymize UUIDv4 identifiers
      --report                Print summary report of scrubbed findings to stderr
      --json                  Output audit report as JSON (for audit command)
      --fail-on-findings      Exit with code 1 if any sensitive items are found (for CI/pre-commit)
  -h, --help                  Show this help message
  -v, --version               Show version

EXAMPLES:
  # Sanitize a browser HAR capture and save an encrypted reversible vault
  trace-scrub clean capture.har -o capture.safe.har -m .scrub-map.json -p "my-secret" --report

  # Audit a log or HAR file in CI and fail if secrets/PII are present
  trace-scrub audit app.jsonl --fail-on-findings

  # Restore real hostnames, IPs, and tokens in an LLM debugging response
  trace-scrub restore ai-answer.md -m .scrub-map.json -p "my-secret"
`.trim();

function readInputContent(fileArg?: string): string {
  if (fileArg && fileArg !== '-') {
    return fs.readFileSync(fileArg, 'utf8');
  }
  if (!process.stdin.isTTY) {
    return fs.readFileSync(0, 'utf8');
  }
  throw new Error(
    'No input file specified and stdin is a TTY. Run "trace-scrub --help" for usage.'
  );
}

function formatReportTable(
  findings: Finding[],
  stats: ScrubStats,
  format: string
): string {
  const lines: string[] = [];
  lines.push(`\n=== trace-scrub Summary (Format: ${format.toUpperCase()}) ===`);
  lines.push(
    `Total Replacements: ${stats.totalReplacements} | Unique Sensitive Entities: ${stats.uniqueSecretsScrubbed}`
  );

  if (findings.length === 0) {
    lines.push('No secrets, tokens, or PII detected.');
    return lines.join('\n');
  }

  lines.push('');
  lines.push(
    `${'CATEGORY'.padEnd(15)} ${'COUNT'.padEnd(7)} ${'PSEUDONYM'.padEnd(36)} ${'FIRST SEEN AT'}`
  );
  lines.push('-'.repeat(90));

  for (const f of findings) {
    const cat = f.category.padEnd(15);
    const cnt = String(f.count).padEnd(7);
    const pseudo =
      f.replacement.length > 34
        ? `${f.replacement.slice(0, 31)}...`.padEnd(36)
        : f.replacement.padEnd(36);
    lines.push(`${cat} ${cnt} ${pseudo} ${f.location}`);
  }
  lines.push('');
  return lines.join('\n');
}

export function runCli(argv: string[] = process.argv.slice(2)): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      output: { type: 'string', short: 'o' },
      format: { type: 'string', short: 'f', default: 'auto' },
      map: { type: 'string', short: 'm' },
      passphrase: { type: 'string', short: 'p' },
      salt: { type: 'string', short: 's' },
      'keep-hostnames': { type: 'boolean', default: false },
      'no-scrub-uuids': { type: 'boolean', default: false },
      report: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
      'fail-on-findings': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false }
    }
  });

  if (values.help || positionals.length === 0) {
    process.stdout.write(HELP_TEXT + '\n');
    return 0;
  }

  if (values.version) {
    process.stdout.write('0.1.0\n');
    return 0;
  }

  const command = positionals[0]!;
  const inputFile = positionals[1];

  try {
    if (command === 'clean') {
      const content = readInputContent(inputFile);
      const { result, engine } = scrubTrace(content, {
        format: (values.format as InputFormat) ?? 'auto',
        filePath: inputFile,
        salt: values.salt,
        keepHostnames: Boolean(values['keep-hostnames']),
        scrubUuids: !values['no-scrub-uuids']
      });

      if (values.map) {
        const vault = engine.exportVault();
        saveVaultToFile(values.map, vault, values.passphrase);
      }

      if (values.output) {
        fs.writeFileSync(values.output, result.output, 'utf8');
      } else {
        process.stdout.write(result.output);
        if (!result.output.endsWith('\n')) {
          process.stdout.write('\n');
        }
      }

      if (values.report) {
        process.stderr.write(
          formatReportTable(result.findings, result.stats, result.format) + '\n'
        );
      }

      return 0;
    }

    if (command === 'audit') {
      const content = readInputContent(inputFile);
      const { result } = scrubTrace(content, {
        format: (values.format as InputFormat) ?? 'auto',
        filePath: inputFile,
        salt: values.salt,
        keepHostnames: Boolean(values['keep-hostnames']),
        scrubUuids: !values['no-scrub-uuids']
      });

      if (values.json) {
        process.stdout.write(
          JSON.stringify(
            {
              format: result.format,
              stats: result.stats,
              findings: result.findings
            },
            null,
            2
          ) + '\n'
        );
      } else {
        process.stdout.write(
          formatReportTable(result.findings, result.stats, result.format) + '\n'
        );
      }

      if (values['fail-on-findings'] && result.findings.length > 0) {
        return 1;
      }
      return 0;
    }

    if (command === 'restore') {
      if (!values.map) {
        throw new Error('The "restore" command requires --map <vault-file>.');
      }
      const content = readInputContent(inputFile);
      const vault = loadVaultFromFile(values.map, values.passphrase);
      const restored = restoreFromVault(content, vault);

      if (values.output) {
        fs.writeFileSync(values.output, restored, 'utf8');
      } else {
        process.stdout.write(restored);
      }
      return 0;
    }

    throw new Error(`Unknown command "${command}". Run "trace-scrub --help" for usage.`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${msg}\n`);
    return 1;
  }
}

// Execute when run directly as CLI
const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('cli.ts'));

if (isMain) {
  process.exitCode = runCli();
}
