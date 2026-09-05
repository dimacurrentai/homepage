import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import * as oidc from 'openid-client';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { fixture } from './fixture.js';
import { Accounts, Memory, memoryAdapter } from '../src/memory.js';
import { createProvider } from '../src/provider.js';

let service, browser;
before(async () => {
  service = await fixture();
  browser = await chromium.launch({ ...(process.env.PLAYWRIGHT_CHANNEL ? { channel: process.env.PLAYWRIGHT_CHANNEL } : {}) });
});
after(async () => { await browser?.close(); await service?.close(); });

async function browserSession(t) {
  const context = await browser.newContext();
  t.after(() => context.close());
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.setDefaultNavigationTimeout(10000);
  return { context, page };
}
async function googleLogin(page) {
  await page.goto(`${service.origin}/auth/google`);
  await page.waitForURL(`${service.origin}/account`);
  assert.match(await page.locator('h1').textContent(), /^Current \d{6}$/);
}
async function approve(page) {
  for (let n = 0; n < 3 && new URL(page.url()).pathname.startsWith('/interaction/'); n++) {
    assert.ok(await page.locator('button[value="approve"]').count(), await page.locator('body').innerText());
    await page.locator('button[value="approve"]').click();
    await page.waitForLoadState('load');
  }
}
async function register(overrides = {}) {
  const response = await fetch(`${service.origin}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${service.settings.registrationToken}` },
    body: JSON.stringify({ redirect_uris: [`${service.origin}/test-callback`], response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'client_secret_basic', ...overrides }),
  });
  assert.equal(response.status, 201, await response.clone().text());
  return response.json();
}
async function authorization(page, client, extra = {}, method = 'GET') {
  const verifier = oidc.randomPKCECodeVerifier();
  const params = new URLSearchParams({ client_id: client.client_id, redirect_uri: client.redirect_uris[0], response_type: 'code', scope: 'openid profile email offline_access', prompt: 'consent', state: 'test-state', nonce: 'test-nonce', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256', ...extra });
  if (method === 'POST') {
    const initial = await page.request.post(`${service.origin}/oauth/authorize`, { form: Object.fromEntries(params), maxRedirects: 0 });
    assert.ok([302, 303].includes(initial.status()));
    await page.goto(new URL(initial.headers().location, service.origin).href);
  } else await page.goto(`${service.origin}/oauth/authorize?${params}`);
  await approve(page);
  const callback = new URL(page.url());
  assert.equal(callback.pathname, '/test-callback', await page.locator('body').textContent());
  assert.equal(callback.searchParams.get('state'), 'test-state');
  assert.ok(callback.searchParams.get('code'), callback.href);
  return { code: callback.searchParams.get('code'), verifier };
}
async function token(client, body) {
  return fetch(`${service.origin}/oauth/token`, {
    method: 'POST', headers: { Authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
  });
}

test('Google creates a six-digit Current account and separate browsers reuse only the verified upstream identity', async t => {
  const { page } = await browserSession(t);
  await googleLogin(page);
  const first = await page.locator('h1').textContent();
  const { page: second } = await browserSession(t);
  await googleLogin(second);
  assert.equal(await second.locator('h1').textContent(), first);
  const other = new Accounts().fromGoogle({ sub: 'same-user' });
  assert.notEqual(other.sub, [...service.accounts.bySub.keys()][0]);
});

test('OIDC client completes discovery, consent, signature verification and UserInfo; dima.ai has its own cookie session', async t => {
  const { page, context } = await browserSession(t);
  await googleLogin(page);
  await page.goto(`${service.origin}/demo/oidc`);
  await approve(page);
  await page.waitForURL(`${service.origin}/account`);
  let result = JSON.parse(await page.locator('pre').textContent());
  assert.equal(result.type, 'oidc');
  assert.equal(result.claims.iss, service.origin);
  assert.equal(result.profile.sub, result.claims.sub);
  assert.ok(result.checks.includes('JWKS signature'));
  await page.goto(`${service.settings.dimaOrigin}/current-demo/login`);
  await approve(page);
  await page.waitForURL(`${service.settings.dimaOrigin}/current-demo`);
  result = JSON.parse(await page.locator('pre').textContent());
  assert.equal(result.type, 'dima');
  assert.equal(result.claims.aud, 'current-dima-demo');
  const cookies = await context.cookies();
  assert.ok(cookies.some(c => c.name === 'current-demo' && c.domain === 'localhost' && c.httpOnly));
  assert.ok(cookies.some(c => c.name === 'current-demo' && c.domain === '127.0.0.1' && c.httpOnly));
});

test('GitHub exchanges a browser-bound PKCE code for a profile without creating a Current account', async t => {
  const { page } = await browserSession(t);
  const response = await page.request.get(`${service.origin}/auth/github`, { maxRedirects: 0 });
  const start = new URL(response.headers().location);
  assert.equal(start.origin, 'https://github.com');
  assert.equal(start.searchParams.get('scope'), 'read:user');
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    if (String(input) === 'https://github.com/login/oauth/access_token') {
      const body = new URLSearchParams(init.body);
      assert.equal(body.get('client_id'), 'test-github');
      assert.equal(body.get('client_secret'), 'github-secret');
      assert.equal(body.get('redirect_uri'), `${service.origin}/auth/github/callback`);
      assert.equal(await oidc.calculatePKCECodeChallenge(body.get('code_verifier')), start.searchParams.get('code_challenge'));
      return Response.json({ access_token: 'github-test-token', token_type: 'bearer', scope: 'read:user' });
    }
    if (String(input) === 'https://api.github.com/user') {
      assert.equal(new Headers(init.headers).get('authorization'), 'Bearer github-test-token');
      return Response.json({ id: 12345, login: 'demo-person', name: 'Demo Person' });
    }
    return realFetch(input, init);
  };
  try {
    await page.goto(`${service.origin}/auth/github/callback?code=test-code&state=${start.searchParams.get('state')}`);
    await page.waitForURL(`${service.origin}/account`);
    const result = JSON.parse(await page.locator('pre').textContent());
    assert.equal(result.type, 'github');
    assert.equal(result.profile.login, 'demo-person');
    assert.equal((await (await page.request.get(`${service.origin}/api/session`)).json()).account, null);
  } finally { globalThis.fetch = realFetch; }
});

test('OAuth-only client gets a protected profile without an ID token', async t => {
  const { page } = await browserSession(t);
  await googleLogin(page);
  await page.goto(`${service.origin}/demo/oauth`);
  await approve(page);
  await page.waitForURL(`${service.origin}/account`);
  const result = JSON.parse(await page.locator('pre').textContent());
  assert.equal(result.type, 'oauth');
  assert.equal(result.claims, null);
  assert.match(result.profile.current_id, /^\d{6}$/);
  assert.equal((await fetch(`${service.origin}/api/identity`)).status, 401);
});

test('xmemory uses its exact callback and Basic authentication without requiring PKCE from the confidential client', async t => {
  const { page } = await browserSession(t);
  const client = service.clients.find(item => item.client_id === 'xmemory');
  assert.equal(client.application_type, 'web');
  const callbackUri = 'https://dk.xmemory.ai/console/login/sso/callback';
  // Intercept the relying party: no test request or authorization code leaves the fixture.
  await page.route(`${callbackUri}?*`, route => route.fulfill({ contentType: 'text/html', body: 'Callback received.' }));
  await googleLogin(page);
  const params = new URLSearchParams({ client_id: 'xmemory', redirect_uri: callbackUri, response_type: 'code', scope: 'openid email profile', state: 'xmemory-state', nonce: 'xmemory-nonce' });
  await page.goto(`${service.origin}/oauth/authorize?${params}`);
  await approve(page);
  const callback = new URL(page.url());
  assert.equal(callback.origin + callback.pathname, callbackUri);
  assert.equal(callback.searchParams.get('state'), 'xmemory-state');
  const code = callback.searchParams.get('code');
  assert.ok(code);
  const body = { grant_type: 'authorization_code', code, redirect_uri: callbackUri };
  const rejected = await token({ ...client, client_secret: 'wrong-secret' }, body);
  assert.equal(rejected.status, 401);
  const response = await token(client, body);
  assert.equal(response.status, 200);
  const tokens = await response.json();
  const jwks = await (await fetch(`${service.origin}/oauth/jwks`)).json();
  const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), { issuer: service.origin, audience: 'xmemory' });
  assert.equal(payload.nonce, 'xmemory-nonce');
  const userinfo = await (await fetch(`${service.origin}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json();
  assert.equal(userinfo.sub, payload.sub);
  assert.equal(userinfo.email, 'demo@example.com');
  assert.equal(userinfo.email_verified, true);
  for (const uri of [`${callbackUri}/`, 'https://wrong.example/console/login/sso/callback']) {
    params.set('redirect_uri', uri);
    const invalid = await fetch(`${service.origin}/oauth/authorize?${params}`, { redirect: 'manual' });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.headers.get('location'), null);
  }
});

test('xmemory registration is restored with stable credentials and is disabled without its secret', async () => {
  const restored = await createProvider(service.settings, new Accounts());
  const client = await restored.provider.Client.find('xmemory');
  assert.equal(client.clientSecret, service.settings.xmemoryClientSecret);
  assert.equal(client.tokenEndpointAuthMethod, 'client_secret_basic');
  const disabled = await createProvider({ ...service.settings, xmemoryClientSecret: undefined }, new Accounts());
  assert.equal(await disabled.provider.Client.find('xmemory'), undefined);
});

test('sign-out clears the local account and the Current provider SSO session', async t => {
  const { page } = await browserSession(t);
  await googleLogin(page);
  await page.goto(`${service.origin}/demo/oidc`);
  await approve(page);
  await page.getByRole('button', { name: 'Sign out of Current' }).click();
  await page.getByRole('button', { name: 'Yes, sign me out' }).click();
  assert.equal((await (await page.request.get(`${service.origin}/api/session`)).json()).account, null);
  const client = service.clients.find(c => c.client_id === 'current-oidc-demo');
  const params = new URLSearchParams({ client_id: client.client_id, redirect_uri: client.redirect_uris[0], response_type: 'code', scope: 'openid', prompt: 'none' });
  const response = await page.request.get(`${service.origin}/oauth/authorize?${params}`, { maxRedirects: 0 });
  assert.equal(new URL(response.headers().location).searchParams.get('error'), 'login_required');
});

test('authorization code, independent JWKS verification, refresh rotation, introspection, revocation and replay rejection', async t => {
  const { page } = await browserSession(t);
  await googleLogin(page);
  const client = await register();
  const grant = await authorization(page, client, {}, 'POST');
  const request = { grant_type: 'authorization_code', code: grant.code, redirect_uri: client.redirect_uris[0], code_verifier: grant.verifier };
  const response = await token(client, request);
  assert.equal(response.status, 200, await response.clone().text());
  const tokens = await response.json();
  assert.ok(tokens.refresh_token);
  const jwks = await (await fetch(`${service.origin}/oauth/jwks`)).json();
  const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), { issuer: service.origin, audience: client.client_id, algorithms: ['RS256'] });
  assert.equal(payload.nonce, 'test-nonce');
  const profile = await (await fetch(`${service.origin}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json();
  assert.equal(profile.sub, payload.sub);
  const auth = { Authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' };
  const introspect = async access => (await fetch(`${service.origin}/oauth/introspect`, { method: 'POST', headers: auth, body: new URLSearchParams({ token: access }) })).json();
  assert.equal((await introspect(tokens.access_token)).active, true);
  const refreshed = await token(client, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
  assert.equal(refreshed.status, 200);
  const fresh = await refreshed.json();
  assert.ok(fresh.refresh_token);
  assert.notEqual(fresh.refresh_token, tokens.refresh_token);
  const revoked = await fetch(`${service.origin}/oauth/revoke`, { method: 'POST', headers: auth, body: new URLSearchParams({ token: fresh.access_token }) });
  assert.equal(revoked.status, 200);
  assert.equal((await introspect(fresh.access_token)).active, false);
  assert.equal((await token(client, request)).status, 400);
  const deletion = await fetch(client.registration_client_uri, {
    method: 'DELETE', headers: { Authorization: `Bearer ${client.registration_access_token}` },
  });
  assert.equal(deletion.status, 204);
  assert.equal((await token(client, { grant_type: 'refresh_token', refresh_token: fresh.refresh_token })).status, 401);
});

test('wrong PKCE, redirect URI, unauthenticated registration and prompt=none are rejected', async t => {
  const { page } = await browserSession(t);
  const client = await register();
  const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: 'https://evil.example/cb', response_type: 'code', scope: 'openid' });
  const invalid = await fetch(`${service.origin}/oauth/authorize?${query}`, { redirect: 'manual' });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.headers.get('location'), null);
  query.set('redirect_uri', client.redirect_uris[0]); query.set('prompt', 'none');
  const silent = await fetch(`${service.origin}/oauth/authorize?${query}`, { redirect: 'manual' });
  assert.equal(new URL(silent.headers.get('location')).searchParams.get('error'), 'login_required');
  assert.equal((await fetch(`${service.origin}/oauth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
  await googleLogin(page);
  const grant = await authorization(page, client);
  assert.equal((await token(client, { grant_type: 'authorization_code', code: grant.code, redirect_uri: client.redirect_uris[0], code_verifier: oidc.randomPKCECodeVerifier() })).status, 400);
});

test('client rejects a callback from another browser and rejects issuer, audience, expiry, nonce, signature and subject substitution', async t => {
  const { page } = await browserSession(t);
  const start = await page.request.get(`${service.origin}/auth/google`, { maxRedirects: 0 });
  const authorizationUrl = new URL(start.headers().location);
  const state = authorizationUrl.searchParams.get('state');
  const rejected = await fetch(`${service.origin}/auth/google/callback?code=stolen&state=${state}`);
  assert.equal(rejected.status, 400);
  for (const kind of ['issuer', 'audience', 'expiry', 'nonce', 'signature', 'subject']) {
    service.control.tamper = kind;
    const { page: isolated } = await browserSession(t);
    await isolated.goto(`${service.origin}/auth/google`);
    assert.equal(await isolated.locator('h1').textContent(), 'Could not continue.', kind);
    assert.equal((await (await isolated.request.get(`${service.origin}/api/session`)).json()).account, null, kind);
  }
  service.control.tamper = null;
});

test('client registration and consent require CSRF protection; cancellation returns access_denied', async t => {
  const { page } = await browserSession(t);
  await googleLogin(page);
  assert.equal((await page.request.post(`${service.origin}/clients`, { form: { name: 'Injected', redirect_uri: 'https://evil.example' } })).status(), 403);
  await page.goto(`${service.origin}/clients`);
  await page.getByLabel('Service name').fill('My sample app');
  await page.getByLabel('Callback URL').fill('https://my-app.example/callback');
  await page.getByRole('button', { name: 'Create client' }).click();
  const credentials = JSON.parse(await page.locator('pre').textContent());
  assert.ok(credentials.client_secret);
  await page.goto(`${service.origin}/demo/oidc`);
  const response = await page.request.post(page.url(), { form: { action: 'approve', csrf: 'wrong' } });
  assert.equal(response.status(), 403);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(await page.locator('h1').textContent(), 'Could not continue.');
});

test('public MCP works with the official SDK, retains latest five, rejects bad input and foreign origins', async t => {
  const client = new Client({ name: 'current-integration-test', version: '1' });
  const transport = new StreamableHTTPClientTransport(new URL(`${service.origin}/mcp`));
  t.after(() => client.close());
  await client.connect(transport);
  assert.deepEqual((await client.listTools()).tools.map(x => x.name), ['assign_color', 'latest_colors']);
  for (let i = 0; i < 7; i++) {
    const result = await client.callTool({ name: 'assign_color', arguments: { name: `Visitor ${i}` } });
    assert.match(result.structuredContent.assignment.hex, /^#[0-9A-F]{6}$/);
  }
  const latest = (await client.callTool({ name: 'latest_colors', arguments: {} })).structuredContent.latest;
  assert.equal(latest.length, 5);
  assert.deepEqual(latest.map(x => x.name), ['Visitor 6', 'Visitor 5', 'Visitor 4', 'Visitor 3', 'Visitor 2']);
  assert.equal((await client.callTool({ name: 'assign_color', arguments: { name: ' '.repeat(61) } })).isError, true);
  assert.equal(JSON.parse((await client.readResource({ uri: 'current://colors/latest' })).contents[0].text).length, 5);
  assert.equal((await fetch(`${service.origin}/mcp`, { method: 'POST', headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
  assert.equal((await fetch(`${service.origin}/mcp`)).status, 405);
});

test('browser color demo uses MCP and renders submitted markup as text at desktop and mobile sizes', async t => {
  const { page } = await browserSession(t);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(service.origin);
  await page.getByLabel('Public display name').fill('<img src=x onerror=alert(1)>');
  await page.getByRole('button', { name: 'Get a color' }).click();
  await page.locator('#color-status').filter({ hasText: 'your color is' }).waitFor();
  assert.equal(await page.locator('#color-board img').count(), 0);
  assert.equal(await page.locator('#color-board strong').first().textContent(), '<img src=x onerror=alert(1)>');
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  assert.deepEqual(errors, []);
});

test('expiring storage enforces capacity, isolates provider instances and revokes all grant records', async () => {
  const memory = new Memory(1);
  memory.set('expired', 1, -1);
  assert.equal(memory.get('expired'), undefined);
  memory.set('live', 1);
  assert.throws(() => memory.set('extra', 2), /capacity/);
  const A = memoryAdapter(), B = memoryAdapter();
  const access = new A('AccessToken'), refresh = new A('RefreshToken');
  await access.upsert('one', { grantId: 'grant' }, 60);
  await refresh.upsert('two', { grantId: 'grant' }, 60);
  assert.equal(await new B('AccessToken').find('one'), undefined);
  await access.revokeByGrantId('grant');
  assert.equal(await access.find('one'), undefined);
  assert.equal(await refresh.find('two'), undefined);
});
