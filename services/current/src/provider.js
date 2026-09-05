import { readFile } from 'node:fs/promises';
import Provider from 'oidc-provider';
import { generateKeyPair, exportJWK } from 'jose';
import { memoryAdapter, random } from './memory.js';

export async function createProvider(settings, accounts) {
  let jwks;
  if (settings.jwksFile) jwks = JSON.parse(await readFile(settings.jwksFile, 'utf8'));
  else {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true });
    jwks = { keys: [{ ...await exportJWK(privateKey), kid: random(), alg: 'RS256', use: 'sig' }] };
  }
  const clients = ['oauth', 'oidc', 'dima'].map(name => ({
    client_id: `current-${name}-demo`, client_secret: random(),
    client_name: name === 'dima' ? 'dima.ai' : `Current ${name.toUpperCase()} demo`,
    redirect_uris: [name === 'dima' ? `${settings.dimaOrigin}/current-demo/callback` : `${settings.currentOrigin}/demo/${name}/callback`],
    post_logout_redirect_uris: [name === 'dima' ? `${settings.dimaOrigin}/current-demo` : `${settings.currentOrigin}/`],
    response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: 'client_secret_basic',
  }));
  const registrationToken = settings.registrationToken || random();
  const provider = new Provider(settings.currentOrigin, {
    adapter: memoryAdapter(), clients, jwks,
    cookies: { keys: [random()], short: { sameSite: 'lax' }, long: { sameSite: 'lax' } },
    claims: { openid: ['sub'], profile: ['name', 'current_id'], email: ['email', 'email_verified'] },
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    subjectTypes: ['public'],
    // A complete authorization-code provider. Implicit/hybrid profiles are not advertised.
    responseTypes: ['code'],
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: registrationToken },
      revocation: { enabled: true, allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId },
      introspection: { enabled: true, allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId },
      claimsParameter: { enabled: true },
    },
    rotateRefreshToken: () => true,
    ttl: {
      AccessToken: 600, AuthorizationCode: 60, IdToken: 600,
      RefreshToken: ctx => ctx?.oidc?.entities.RotatedRefreshToken?.remainingTTL ?? 3600,
      Session: 3600, Interaction: 600, Grant: 3600,
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    routes: {
      authorization: '/oauth/authorize', token: '/oauth/token', jwks: '/oauth/jwks',
      userinfo: '/oauth/userinfo', registration: '/oauth/register',
      revocation: '/oauth/revoke', introspection: '/oauth/introspect', end_session: '/oauth/logout',
    },
    clientBasedCORS: (_ctx, origin, client) => client.redirectUris.some(uri => new URL(uri).origin === origin),
    findAccount: async (_ctx, id) => {
      const account = accounts.bySub.get(id);
      if (!account) return undefined;
      return { accountId: id, claims: async () => ({ ...account }) };
    },
    renderError: async (ctx, out) => {
      ctx.type = 'html';
      // Error descriptions can contain caller-controlled strings. Keep this page static.
      ctx.body = '<!doctype html><title>Sign-in could not continue</title><h1>Sign-in could not continue</h1><p>The request is invalid or has expired. Return to the service and start again.</p><a href="/">Current demos</a>';
    },
  });
  provider.proxy = true;
  // Never log authorization codes, tokens, or provider response bodies.
  provider.on('server_error', (_ctx, err) => console.error('OIDC server error:', err.name));
  return { provider, clients, registrationToken };
}
