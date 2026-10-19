import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deserializeVault,
  restoreFromVault,
  scrubTrace,
  serializeVault
} from '../src/index.js';

function createSampleJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'prod-signing-key-99' })
  ).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = Buffer.from('real-hmac-signature-bytes-1234567890').toString('base64url');
  return `${header}.${body}.${sig}`;
}

describe('trace-scrub — Relational & Format-Preserving Sanitizer', () => {
  it('preserves JWT 3-part base64url structure and timestamps while scrubbing PII & re-signing', () => {
    const jwt = createSampleJwt({
      sub: 'usr_99887766',
      email: 'alice@corp.internal',
      name: 'Alice Vance',
      exp: 1893456000,
      iat: 1893452400,
      scope: 'read:users write:billing'
    });

    const { result } = scrubTrace(JSON.stringify({ token: jwt }), {
      format: 'json',
      salt: 'unit-test-salt'
    });

    const parsed = JSON.parse(result.output) as { token: string };
    assert.notEqual(parsed.token, jwt);

    const parts = parsed.token.split('.');
    assert.equal(parts.length, 3, 'Scrubbed JWT must have 3 base64url segments');

    const decodedHeader = JSON.parse(
      Buffer.from(parts[0]!, 'base64url').toString('utf8')
    ) as Record<string, unknown>;
    const decodedPayload = JSON.parse(
      Buffer.from(parts[1]!, 'base64url').toString('utf8')
    ) as Record<string, unknown>;

    assert.equal(decodedHeader.alg, 'HS256');
    assert.equal(decodedHeader.typ, 'JWT');
    assert.notEqual(decodedHeader.kid, 'prod-signing-key-99');

    // Timestamps and scopes preserved
    assert.equal(decodedPayload.exp, 1893456000);
    assert.equal(decodedPayload.iat, 1893452400);
    assert.equal(decodedPayload.scope, 'read:users write:billing');

    // Identity claims scrubbed
    assert.equal(decodedPayload.email, 'user-01@domain-01.example');
    assert.notEqual(decodedPayload.sub, 'usr_99887766');
    assert.notEqual(decodedPayload.name, 'Alice Vance');
  });

  it('maintains relational consistency across multi-entry HAR captures (tokens, cookies, emails, domains, IPs)', () => {
    const jwtA = createSampleJwt({
      sub: 'alice-123',
      email: 'alice@acme-sec.io',
      exp: 1900000000
    });

    const sampleHar = {
      log: {
        version: '1.2',
        creator: { name: 'DevTools', version: '1.0' },
        entries: [
          {
            serverIPAddress: '10.42.8.19',
            request: {
              method: 'POST',
              url: 'https://auth.acme-sec.io/v1/login?api_key=ghp_1234567890abcdefghijklmnopqrstuv',
              headers: [
                { name: 'Host', value: 'auth.acme-sec.io' },
                { name: 'Content-Type', value: 'application/json' }
              ],
              cookies: [],
              queryString: [
                { name: 'api_key', value: 'ghp_1234567890abcdefghijklmnopqrstuv' }
              ],
              postData: {
                mimeType: 'application/json',
                text: JSON.stringify({
                  email: 'alice@acme-sec.io',
                  colleague: 'bob@acme-sec.io',
                  password: 'SuperSecretPassword!2026'
                })
              }
            },
            response: {
              status: 200,
              headers: [
                {
                  name: 'Set-Cookie',
                  value: 'sid=live_session_secret_xyz987; Path=/; Domain=.acme-sec.io; HttpOnly; Secure'
                }
              ],
              cookies: [
                { name: 'sid', value: 'live_session_secret_xyz987', domain: '.acme-sec.io' }
              ],
              content: {
                mimeType: 'application/json',
                text: JSON.stringify({
                  access_token: jwtA,
                  user_id: '550e8400-e29b-41d4-a716-446655440000',
                  client_ip: '10.42.8.19'
                })
              }
            }
          },
          {
            serverIPAddress: '10.42.8.19',
            request: {
              method: 'GET',
              url: 'https://api.acme-sec.io/v1/users/550e8400-e29b-41d4-a716-446655440000',
              headers: [
                { name: 'Host', value: 'api.acme-sec.io' },
                { name: 'Authorization', value: `Bearer ${jwtA}` },
                { name: 'Cookie', value: 'sid=live_session_secret_xyz987' }
              ],
              cookies: [{ name: 'sid', value: 'live_session_secret_xyz987' }],
              queryString: []
            },
            response: {
              status: 200,
              headers: [],
              cookies: [],
              content: {
                mimeType: 'application/json',
                text: JSON.stringify({
                  id: '550e8400-e29b-41d4-a716-446655440000',
                  email: 'alice@acme-sec.io'
                })
              }
            }
          }
        ]
      }
    };

    const { result } = scrubTrace(JSON.stringify(sampleHar), {
      format: 'auto',
      salt: 'har-test-salt'
    });

    assert.equal(result.format, 'har');
    assert.ok(!result.output.includes('alice@acme-sec.io'));
    assert.ok(!result.output.includes('bob@acme-sec.io'));
    assert.ok(!result.output.includes('SuperSecretPassword!2026'));
    assert.ok(!result.output.includes('live_session_secret_xyz987'));
    assert.ok(!result.output.includes('ghp_1234567890abcdefghijklmnopqrstuv'));
    assert.ok(!result.output.includes('10.42.8.19'));
    assert.ok(!result.output.includes('550e8400-e29b-41d4-a716-446655440000'));

    const scrubbedHar = JSON.parse(result.output) as typeof sampleHar;
    const entry0 = scrubbedHar.log.entries[0]!;
    const entry1 = scrubbedHar.log.entries[1]!;

    // 1. Same IP across both entries and inside JSON response body -> 192.0.2.1 (RFC 5737 TEST-NET-1 for 10.x)
    assert.equal(entry0.serverIPAddress, '192.0.2.1');
    assert.equal(entry1.serverIPAddress, '192.0.2.1');
    const resp0Body = JSON.parse(entry0.response.content.text) as Record<string, string>;
    assert.equal(resp0Body.client_ip, '192.0.2.1');

    // 2. Domain-grouped emails and hostnames share domain-01.example
    const req0Body = JSON.parse(entry0.request.postData!.text) as Record<string, string>;
    assert.equal(req0Body.email, 'user-01@domain-01.example');
    assert.equal(req0Body.colleague, 'user-02@domain-01.example');
    assert.equal(entry0.request.headers[0]!.value, 'host-01.domain-01.example');
    assert.equal(entry1.request.headers[0]!.value, 'host-02.domain-01.example');

    // 3. JWT returned in Entry 0 response matches Bearer JWT sent in Entry 1 request
    const issuedJwt = resp0Body.access_token!;
    assert.equal(entry1.request.headers[1]!.value, `Bearer ${issuedJwt}`);

    // 4. Set-Cookie sid in Entry 0 matches Cookie sid in Entry 1
    const cookieVal0 = entry0.response.cookies[0]!.value;
    const cookieVal1 = entry1.request.cookies[0]!.value;
    assert.equal(cookieVal0, cookieVal1);

    // 5. UUID in Entry 0 response matches URL path and JSON body in Entry 1
    const uuid0 = resp0Body.user_id!;
    assert.ok(entry1.request.url.endsWith(`/${uuid0}`));
    const resp1Body = JSON.parse(entry1.response.content.text) as Record<string, string>;
    assert.equal(resp1Body.id, uuid0);
  });

  it('scrubs .env files and database connection URIs while preserving comments and public config', () => {
    const envInput = [
      '# Production configuration',
      'PORT=8080',
      'NODE_ENV=production',
      'DATABASE_URL="postgres://dbadmin:P@ssw0rd99!@db.internal.corp:5432/appdb"',
      'OPENAI_API_KEY=sk-proj-abcdef1234567890abcdef1234567890',
      'WEBHOOK_SECRET=whsec_99887766554433221100'
    ].join('\n');

    const { result } = scrubTrace(envInput, { format: 'auto', salt: 'env-salt' });
    assert.equal(result.format, 'env');
    assert.ok(result.output.includes('# Production configuration'));
    assert.ok(result.output.includes('PORT=8080'));
    assert.ok(result.output.includes('NODE_ENV=production'));
    assert.ok(!result.output.includes('P@ssw0rd99!'));
    assert.ok(!result.output.includes('db.internal.corp'));
    assert.ok(!result.output.includes('sk-proj-abcdef1234567890abcdef1234567890'));
    assert.ok(result.output.includes('sk-proj-scrub-01_'));
    assert.ok(!result.output.includes('whsec_99887766554433221100'));
  });

  it('supports encrypted AES-256-GCM vault serialization and round-trip restoration', () => {
    const rawLog =
      'curl -X POST https://api.payments-internal.io/v1/charge -H "Authorization: Bearer sk-live-9876543210abcdef98765432" -d \'{"email":"ceo@payments-internal.io","ip":"192.168.10.55"}\'';

    const { result, engine } = scrubTrace(rawLog, {
      format: 'text',
      salt: 'vault-test-salt'
    });

    assert.ok(!result.output.includes('payments-internal.io'));
    assert.ok(!result.output.includes('sk-live-9876543210abcdef98765432'));
    assert.ok(!result.output.includes('192.168.10.55'));

    const vault = engine.exportVault();
    const encryptedJson = serializeVault(vault, 'correct-horse-battery-staple');
    assert.ok(!encryptedJson.includes('payments-internal.io'), 'Encrypted vault must not leak plaintext');

    // Wrong passphrase must fail
    assert.throws(() => {
      deserializeVault(encryptedJson, 'wrong-passphrase');
    }, /Failed to decrypt vault file/);

    // Correct passphrase decrypts and restores original values
    const decryptedVault = deserializeVault(
      encryptedJson,
      'correct-horse-battery-staple'
    );
    const restored = restoreFromVault(result.output, decryptedVault);
    assert.equal(restored, rawLog);
  });
});
