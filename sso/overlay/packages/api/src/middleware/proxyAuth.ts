import type { NextFunction, Request, Response } from 'express';
import { serializeError } from 'serialize-error';

import { createTeam } from '@/controllers/team';
import Team from '@/models/team';
import User from '@/models/user';
import { setupTeamDefaults } from '@/setupDefaults';
import logger from '@/utils/logger';

const env = process.env;

// Trust identity headers injected by an authenticating reverse proxy
// (e.g. oauth2-proxy / Dex). SECURITY: only enable when HyperDX is reachable
// *exclusively* through that proxy and the proxy strips any client-supplied
// copies of these headers — otherwise a client could spoof the identity.
export const PROXY_AUTH_ENABLED = env.PROXY_AUTH_ENABLED === 'true';

// Header carrying the authenticated user's email. oauth2-proxy default is
// X-Auth-Request-Email (Node lower-cases header keys in req.headers).
const EMAIL_HEADER = (
  env.PROXY_AUTH_EMAIL_HEADER || 'x-auth-request-email'
).toLowerCase();

// Optional display-name header. oauth2-proxy: X-Auth-Request-Preferred-Username.
const NAME_HEADER = (
  env.PROXY_AUTH_NAME_HEADER || 'x-auth-request-preferred-username'
).toLowerCase();

// HyperDX is single-team; first proxy login bootstraps it.
const DEFAULT_TEAM_NAME = env.PROXY_AUTH_DEFAULT_TEAM_NAME || 'HyperDX';

// Header carrying the user's groups. oauth2-proxy (GitHub provider) emits
// `org` and `org:team` entries in X-Forwarded-Groups.
const GROUPS_HEADER = (
  env.PROXY_AUTH_GROUPS_HEADER || 'x-forwarded-groups'
).toLowerCase();

// Groups granted full access (e.g. "topia-io:devops"). Everyone else is a
// read-only viewer. Empty disables roles: every user keeps full access.
const ADMIN_GROUPS = (env.PROXY_AUTH_ADMIN_GROUPS || '')
  .split(',')
  .map(g => g.trim().toLowerCase())
  .filter(Boolean);

const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

// POST endpoints that only read data (searches, charts, queries) or touch the
// viewer's own UI state, so viewers keep a working UI.
const VIEWER_POST_ALLOWLIST = [
  /^\/clickhouse-proxy\/(?!test(\/|$))/,
  /^\/v1\/prometheus\/query/,
  /^\/ai\/assistant$/,
  /^\/me\/onboarding\//,
];

export function proxyAuthEnabled() {
  return PROXY_AUTH_ENABLED;
}

function headerValue(req: Request, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

function isAdmin(req: Request) {
  const raw = req.headers[GROUPS_HEADER];
  const groups = (Array.isArray(raw) ? raw.join(',') : raw || '')
    .split(',')
    .map(g => g.trim().toLowerCase());
  return groups.some(g => ADMIN_GROUPS.includes(g));
}

// App-level role guard: admins pass through; viewers may only read. Viewer
// ClickHouse queries are forced to readonly=2 so raw SQL sent through the
// proxy cannot modify data either (ClickHouse rejects raising it back).
export function proxyAuthRoleGuard(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (!PROXY_AUTH_ENABLED || ADMIN_GROUPS.length === 0 || isAdmin(req)) {
    return next();
  }

  if (req.path.startsWith('/clickhouse-proxy/')) {
    const url = new URL(req.url, 'http://localhost');
    url.searchParams.set('readonly', '2');
    req.url = `${url.pathname}${url.search}`;
    req.originalUrl = req.url;
  }

  if (
    SAFE_METHODS.includes(req.method) ||
    (req.method === 'POST' &&
      VIEWER_POST_ALLOWLIST.some(re => re.test(req.path)))
  ) {
    return next();
  }

  logger.warn(
    {
      method: req.method,
      path: req.path,
      email: headerValue(req, EMAIL_HEADER),
    },
    'Proxy auth: write denied for viewer',
  );
  return res.status(403).json({ message: 'Read-only access' });
}

// Ensure the single HyperDX team exists, tolerating a concurrent first-login
// race (createTeam throws if a team already exists).
async function getOrCreateTeam() {
  const existing = await Team.findOne({});
  if (existing) {
    return existing;
  }
  try {
    const team = await createTeam({
      name: DEFAULT_TEAM_NAME,
      collectorAuthenticationEnforced: true,
    });
    try {
      await setupTeamDefaults(team._id.toString());
    } catch (error) {
      logger.error(
        { err: serializeError(error) },
        'Proxy auth: failed to set up team defaults',
      );
    }
    return team;
  } catch (err) {
    const team = await Team.findOne({});
    if (team) {
      return team;
    }
    throw err;
  }
}

// Find-or-provision the user named by the proxy header, attach to the single
// team, and establish a passport session. Identity is asserted by the proxy,
// so the provisioned user has no local password (passport-local is bypassed).
export async function proxyAuthenticate(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const email = headerValue(req, EMAIL_HEADER)?.trim().toLowerCase();
    if (!email) {
      logger.warn(
        { header: EMAIL_HEADER },
        'Proxy auth enabled but identity header missing on request',
      );
      return res.sendStatus(401);
    }

    let user = await User.findOne({ email });

    if (!user) {
      const team = await getOrCreateTeam();
      const name = headerValue(req, NAME_HEADER)?.trim() || email;
      try {
        user = await new User({ email, name, team: team._id }).save();
      } catch (err) {
        // Unique-email race: another concurrent request created the user.
        user = await User.findOne({ email });
        if (!user) {
          throw err;
        }
      }
      logger.info(
        { email, type: 'user_login', authType: 'proxy' },
        'Proxy auth: provisioned user',
      );
    }

    return req.login(user, err => {
      if (err) {
        return next(err);
      }
      return next();
    });
  } catch (err) {
    logger.error({ err: serializeError(err) }, 'Proxy auth failed');
    return next(err);
  }
}
