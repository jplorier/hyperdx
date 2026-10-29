const env = process.env;

export function parseGroups(value: string | undefined) {
  return (value || '')
    .split(',')
    .map(g => g.trim().toLowerCase())
    .filter(Boolean);
}

export const SSO_ENABLED = env.SSO_ENABLED === 'true';

// Any OIDC provider; built for Dex fronting GitHub and Google.
export const OIDC_ISSUER = env.SSO_OIDC_ISSUER || '';
export const OIDC_CLIENT_ID = env.SSO_OIDC_CLIENT_ID || '';
export const OIDC_CLIENT_SECRET = env.SSO_OIDC_CLIENT_SECRET || '';
export const OIDC_SCOPES = env.SSO_OIDC_SCOPES || 'openid email profile groups';
export const GROUPS_CLAIM = env.SSO_GROUPS_CLAIM || 'groups';

// Group names as the provider emits them. Dex's GitHub connector gives `org`
// and `org:team-slug`; its Google connector gives group emails. Signing in
// needs at least one of ALLOWED_GROUPS.
export const ALLOWED_GROUPS = parseGroups(env.SSO_ALLOWED_GROUPS);

// Full access. Empty disables roles: every allowed user is admin.
export const ADMIN_GROUPS = parseGroups(env.SSO_ADMIN_GROUPS);

// May author shared content (dashboards, saved searches, alerts, webhooks)
// but not manage sources, connections or the team.
export const MEMBER_GROUPS = parseGroups(env.SSO_MEMBER_GROUPS);

// Roles and group membership are checked at sign-in only, so sessions are cut
// after this long to pick up removals from IdP groups.
export const SESSION_MAX_AGE_MS =
  Number(env.SSO_SESSION_MAX_HOURS ?? 24) * 60 * 60 * 1000;

// Access keys stop working once their owner hasn't signed in for this long,
// so removing someone from the IdP group also revokes their key. 0 disables
// the check.
export const ACCESS_KEY_MAX_IDLE_MS =
  Number(env.SSO_ACCESS_KEY_MAX_IDLE_DAYS ?? 30) * 24 * 60 * 60 * 1000;

export function assertConfig() {
  if (!SSO_ENABLED) {
    return;
  }
  const missing = [
    ['SSO_OIDC_ISSUER', OIDC_ISSUER],
    ['SSO_OIDC_CLIENT_ID', OIDC_CLIENT_ID],
    ['SSO_OIDC_CLIENT_SECRET', OIDC_CLIENT_SECRET],
    ['SSO_ALLOWED_GROUPS', ALLOWED_GROUPS.join(',')],
  ]
    .filter(([, v]) => !v)
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(`SSO_ENABLED=true but ${missing.join(', ')} unset`);
  }
}
