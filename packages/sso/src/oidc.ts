import type * as Client from 'openid-client';

import {
  GROUPS_CLAIM,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  OIDC_ISSUER,
  OIDC_SCOPES,
} from './config';

export interface OidcIdentity {
  email: string;
  name: string;
  groups: string[];
}

// Values that must survive the round trip to the IdP, kept in the session.
export interface PendingLogin {
  state: string;
  nonce: string;
  codeVerifier: string;
}

// openid-client is ESM-only. Loading it on first sign-in keeps it out of
// CommonJS consumers (the API's Jest suites) that never sign in.
const loadClient = () => import('openid-client');

let discovered: Promise<Client.Configuration> | undefined;

function getConfig() {
  // Retry discovery on the next login if the IdP was down at the first one.
  discovered ??= loadClient()
    .then(client =>
      client.discovery(
        new URL(OIDC_ISSUER),
        OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET,
      ),
    )
    .catch(err => {
      discovered = undefined;
      throw err;
    });
  return discovered;
}

export async function startLogin(redirectUri: string) {
  const client = await loadClient();
  const config = await getConfig();
  const pending: PendingLogin = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier: client.randomPKCECodeVerifier(),
  };
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: OIDC_SCOPES,
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(
      pending.codeVerifier,
    ),
    code_challenge_method: 'S256',
  });
  return { url: url.toString(), pending };
}

// Validates state, nonce, PKCE and the ID token signature and claims.
export async function finishLogin(
  callbackUrl: URL,
  pending: PendingLogin,
): Promise<OidcIdentity> {
  const client = await loadClient();
  const config = await getConfig();
  const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: pending.codeVerifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  if (!claims) {
    throw new Error('OIDC response has no ID token');
  }

  const email = typeof claims.email === 'string' ? claims.email : '';
  if (!email || claims.email_verified === false) {
    throw new Error(`OIDC subject ${claims.sub} has no verified email`);
  }

  const rawGroups = claims[GROUPS_CLAIM];
  const groups = Array.isArray(rawGroups)
    ? rawGroups
        .filter((g): g is string => typeof g === 'string')
        .map(g => g.trim().toLowerCase())
        .filter(Boolean)
    : [];

  const name =
    typeof claims.name === 'string' && claims.name ? claims.name : email;

  return { email: email.toLowerCase(), name, groups };
}
