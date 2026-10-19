# `trace-scrub`

**Relational, Format-Preserving Network, HAR & Log Sanitizer for Security Researchers, Reverse Engineers & Developers.**

When sharing HTTP Archive (`.har`) captures, `mitmproxy` dumps, `.env` configs, `curl` commands, or application logs on GitHub issues or with AI coding assistants, standard secret scanners (`gitleaks`, `trufflehog`) either only *detect* secrets or replace them with static strings like `[REDACTED]`. Static redaction breaks downstream parsers (invalidating 3-part base64url JWTs, RFC IPv4/IPv6 syntax, UUIDv4 formats, and nested JSON inside `.har` payloads) and destroys **referential integrity** across multi-step network flows.

`trace-scrub` solves this with **zero runtime dependencies** (built on Node.js native `node:crypto`), performing **deterministic, relational, format-preserving pseudonymization** with an optional **AES-256-GCM encrypted reversible vault** (`restore`).

---

## Key Features

- **Structure-Preserving JWT Sanitization:** Decodes `eyJ...` tokens, preserves structural headers (`alg`, `typ`) and timestamps/scopes (`exp`, `iat`, `nbf`, `scope`), pseudonymizes identity claims (`sub`, `email`, `name`, `jti`, `client_id`), and re-signs with a deterministic HMAC dummy signature so JWT parsers still decode the token cleanly.
- **Domain-Grouped Relational Topology:** `alice@corp.internal` and `bob@corp.internal` become `user-01@domain-01.example` and `user-02@domain-01.example`, while `auth.corp.internal` and `api.corp.internal` become `host-01.domain-01.example` and `host-02.domain-01.example`—preserving organizational and subdomain relationships across requests.
- **Subnet-Aware RFC 5737 IPv4 & IPv6 Mapping:** Maps `10.x.x.x` to `192.0.2.x` (`TEST-NET-1`), `172.16-31.x` / `192.168.x` to `198.51.100.x` (`TEST-NET-2`), public IPs to `203.0.113.x` (`TEST-NET-3`), and IPv6 to `2001:db8::x` while leaving `127.0.0.1` and `localhost` untouched.
- **Deep HTTP Archive (`.har`) 1.2 Sanitization:** Scrubs `serverIPAddress`, URLs, `Authorization` (`Bearer` & `Basic`), `Cookie` / `Set-Cookie` headers (preserving flags like `HttpOnly`, `Secure`, `SameSite`, `Path`), query strings, and recursively scrubs nested JSON / URL-encoded form bodies inside `postData.text` and `response.content.text`.
- **Reversible Local Vault (`--map` + `--passphrase`):** Stateless in-memory salt by default (zero secrets touch disk). Opt-in `--map .scrub-map.json` with optional `scrypt` + `AES-256-GCM` encryption lets you run `trace-scrub restore` on an LLM response or colleague's reply to translate pseudonyms back to real values locally.

---

## Quick Start

### Install & Build

```bash
npm install
npm run build
```

### 1. Audit a Capture or Log (Dry-Run & CI Gate)

```bash
npx trace-scrub audit examples/sample.har
# Exit with code 1 in CI / pre-commit hooks if secrets or PII are found:
npx trace-scrub audit examples/sample.har --fail-on-findings
```

### 2. Sanitize a `.har`, `.jsonl`, `.env`, or `curl` Trace

```bash
# Clean a HAR capture and save an AES-256-GCM encrypted reversible map
npx trace-scrub clean examples/sample.har \
  -o examples/sample.scrubbed.har \
  -m .scrub-map.json \
  -p "my-vault-passphrase" \
  --report
```

### 3. Restore Original Values from an AI / Issue Reply

```bash
npx trace-scrub restore examples/sample.scrubbed.har \
  -m .scrub-map.json \
  -p "my-vault-passphrase"
```

---

## Programmatic API

```ts
import { scrubTrace, serializeVault, deserializeVault, restoreFromVault } from 'trace-scrub';

const { result, engine } = scrubTrace(harFileContent, {
  format: 'auto',
  salt: 'optional-session-salt'
});

console.log(result.stats);
console.log(result.output);

// Export encrypted vault and restore later
const encryptedVault = serializeVault(engine.exportVault(), 'passphrase');
const vault = deserializeVault(encryptedVault, 'passphrase');
const original = restoreFromVault(result.output, vault);
```

---

## License

MIT
