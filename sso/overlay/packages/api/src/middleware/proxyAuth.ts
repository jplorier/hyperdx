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
export const EMAIL_HEADER = (
  env.PROXY_AUTH_EMAIL_HEADER || 'x-auth-request-email'
).toLowerCase();

// Optional display-name header. oauth2-proxy: X-Auth-Request-Preferred-Username.
const NAME_HEADER = (
  env.PROXY_AUTH_NAME_HEADER || 'x-auth-request-preferred-username'
).toLowerCase();

// HyperDX is single-team; first proxy login bootstraps it.
const DEFAULT_TEAM_NAME = env.PROXY_AUTH_DEFAULT_TEAM_NAME || 'HyperDX';

export function proxyAuthEnabled() {
  return PROXY_AUTH_ENABLED;
}

export function headerValue(req: Request, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
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
