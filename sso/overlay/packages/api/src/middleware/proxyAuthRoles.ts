import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { ToolCallback } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type { NextFunction, Request, Response } from 'express';
import type { AnyZodObject } from 'zod';

import ProxyAuthRole, {
  PROXY_AUTH_ROLES,
  type ProxyAuthRoleName,
} from '@/models/proxyAuthRole';
import User from '@/models/user';
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

import { EMAIL_HEADER, headerValue, PROXY_AUTH_ENABLED } from './proxyAuth';

const env = process.env;

// Header carrying the user's groups. oauth2-proxy (GitHub provider) emits
// `org` and `org:team` entries in X-Forwarded-Groups.
const GROUPS_HEADER = (
  env.PROXY_AUTH_GROUPS_HEADER || 'x-forwarded-groups'
).toLowerCase();

function parseGroups(value: string | undefined) {
  return (value || '')
    .split(',')
    .map(g => g.trim().toLowerCase())
    .filter(Boolean);
}

// Groups granted full access (e.g. "topia-io:devops"). Empty disables roles:
// every user keeps full access.
const ADMIN_GROUPS = parseGroups(env.PROXY_AUTH_ADMIN_GROUPS);

// Groups that may author shared content (dashboards, saved searches, alerts,
// webhooks) but not manage sources, connections or the team.
const MEMBER_GROUPS = parseGroups(env.PROXY_AUTH_MEMBER_GROUPS);

// Access keys stop working once their owner hasn't signed in through the
// proxy for this long, so removing someone from the IdP group also revokes
// their key. 0 disables the check.
const ACCESS_KEY_MAX_IDLE_MS =
  Number(env.PROXY_AUTH_ACCESS_KEY_MAX_IDLE_DAYS ?? 30) * 24 * 60 * 60 * 1000;

// Routers authenticated by access key (validateUserAccessKey). Requests to
// them don't go through the proxy session, so the role comes from the key
// owner's last proxy sign-in and request headers are ignored.
const ACCESS_KEY_PATH = /^\/(mcp|api\/v2)(\/|$)/;

const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

// Non-GET routes that only read data or touch the caller's own state.
// /mcp is gated per tool by guardMcpTool.
const VIEWER_WRITES = [
  /^\/clickhouse-proxy\/(?!test(\/|$))/,
  /^\/v1\/prometheus\/query/,
  /^\/ai\/assistant$/,
  /^\/me\/(onboarding\/|accessKey$)/,
  /^\/favorites(\/|$)/,
  /^\/api\/v2\/(search|charts\/series|dashboards\/validate)\/?$/,
  /^\/mcp\/?$/,
];

// Team-shared content members may author. Every other write (sources,
// connections, team, iac, connection tests) needs admin, so routes added
// upstream are denied until they are classified here.
const MEMBER_WRITES = [
  /^\/(dashboards|saved-search|alerts|webhooks|pinned-filters)(\/|$)/,
  /^\/api\/v2\/(dashboards|saved-searches|alerts|webhooks)(\/|$)/,
];

// Refresh the stored role at most this often per user unless it changes.
const RECORD_INTERVAL_MS = 60 * 60 * 1000;
const lastRecorded = new Map<string, { state: string; at: number }>();

const writeDecisions = getCounter('hyperdx.proxy_auth.write_decisions', {
  description:
    'Writes (HTTP and MCP tool calls) checked against proxy-auth roles, ' +
    'labeled by caller role and outcome (allowed/denied).',
});

function hasRole(role: ProxyAuthRoleName, needed: ProxyAuthRoleName) {
  return PROXY_AUTH_ROLES.indexOf(role) >= PROXY_AUTH_ROLES.indexOf(needed);
}

function roleForGroups(groups: string[]): ProxyAuthRoleName {
  if (ADMIN_GROUPS.length === 0 || groups.some(g => ADMIN_GROUPS.includes(g))) {
    return 'admin';
  }
  return groups.some(g => MEMBER_GROUPS.includes(g)) ? 'member' : 'viewer';
}

function requiredRole(req: Request): ProxyAuthRoleName {
  if (
    SAFE_METHODS.includes(req.method) ||
    VIEWER_WRITES.some(re => re.test(req.path))
  ) {
    return 'viewer';
  }
  return MEMBER_WRITES.some(re => re.test(req.path)) ? 'member' : 'admin';
}

function recordRole(
  user: Express.User,
  role: ProxyAuthRoleName,
  groups: string[],
) {
  const userId = user._id.toString();
  const state = `${role}|${groups.join(',')}`;
  const prev = lastRecorded.get(userId);
  if (prev?.state === state && Date.now() - prev.at < RECORD_INTERVAL_MS) {
    return;
  }
  lastRecorded.set(userId, { state, at: Date.now() });

  ProxyAuthRole.findOneAndUpdate(
    { user: user._id },
    { email: user.email, role, groups, lastSeenAt: new Date() },
    { upsert: true },
  )
    .then(old => {
      if (old?.role !== role) {
        logger.info(
          { email: user.email, from: old?.role, to: role, groups },
          'Proxy auth: role changed',
        );
      }
    })
    .catch(err => {
      lastRecorded.delete(userId);
      logger.error({ err, email: user.email }, 'Proxy auth: role not recorded');
    });
}

// App-level role guard. Viewers may only read; members may also author
// shared content; admins pass. Non-admin ClickHouse queries are forced to
// readonly=2 so raw SQL sent through the proxy cannot modify data either
// (ClickHouse rejects raising it back).
export async function proxyAuthRoleGuard(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (!PROXY_AUTH_ENABLED) {
    return next();
  }

  try {
    let role: ProxyAuthRoleName;
    let email: string | undefined;

    if (ACCESS_KEY_PATH.test(req.path)) {
      const key = req.headers.authorization?.split('Bearer ')[1];
      const user = key ? await User.findOne({ accessKey: key }) : null;
      if (!key || !user) {
        // validateUserAccessKey answers 401.
        return next();
      }
      const record = await ProxyAuthRole.findOne({ user: user._id });
      if (
        !record ||
        (ACCESS_KEY_MAX_IDLE_MS > 0 &&
          Date.now() - record.lastSeenAt.getTime() > ACCESS_KEY_MAX_IDLE_MS)
      ) {
        logger.warn(
          { email: user.email, lastSeenAt: record?.lastSeenAt },
          'Proxy auth: access key rejected, no recent sign-in',
        );
        return res.status(403).json({
          message:
            'Access key inactive: sign in to HyperDX in the browser to reactivate it',
        });
      }
      role = record.role;
      email = user.email;
      // The MCP SDK hands req.auth to tool handlers as extra.authInfo.
      const auth: AuthInfo = {
        token: key,
        clientId: user._id.toString(),
        scopes: [],
        extra: { role, email },
      };
      (req as Request & { auth?: AuthInfo }).auth = auth;
    } else {
      email = headerValue(req, EMAIL_HEADER)?.trim().toLowerCase();
      const groups = parseGroups(
        [req.headers[GROUPS_HEADER] ?? []].flat().join(','),
      );
      role = roleForGroups(groups);
      if (req.user && req.user.email?.toLowerCase() !== email) {
        // The session belongs to a different account than the proxy asserts
        // (shared browser, switched IdP user). Drop it so isUserAuthenticated
        // re-provisions from the header instead of mixing two identities.
        req.user = undefined;
      } else if (req.user) {
        recordRole(req.user, role, groups);
      }
    }

    const needed = requiredRole(req);
    const path = req.path;
    if (!hasRole(role, needed)) {
      writeDecisions.add(1, { role, outcome: 'denied' });
      logger.warn(
        { method: req.method, path, email, role, needed },
        'Proxy auth: write denied',
      );
      return res.status(403).json({
        message: `Your role (${role}) cannot do this; it requires ${needed}.`,
      });
    }

    if (role !== 'admin' && path.startsWith('/clickhouse-proxy/')) {
      const url = new URL(req.url, 'http://localhost');
      url.searchParams.set('readonly', '2');
      req.url = `${url.pathname}${url.search}`;
      req.originalUrl = req.url;
    }

    if (needed !== 'viewer') {
      writeDecisions.add(1, { role, outcome: 'allowed' });
      res.on('finish', () => {
        logger.info(
          { method: req.method, path, email, role, status: res.statusCode },
          'Proxy auth: write',
        );
      });
    }

    return next();
  } catch (err) {
    return next(err);
  }
}

// MCP serves every tool over one POST /mcp, so writes are gated per tool:
// tools not marked read-only need member, source tools need admin. Fails
// closed when the guard resolved no role for the request.
export function guardMcpTool(
  name: string,
  annotations: ToolAnnotations | undefined,
  handler: ToolCallback<AnyZodObject>,
): ToolCallback<AnyZodObject> {
  const needed: ProxyAuthRoleName = annotations?.readOnlyHint
    ? 'viewer'
    : name.endsWith('_source')
      ? 'admin'
      : 'member';
  if (!PROXY_AUTH_ENABLED || needed === 'viewer') {
    return handler;
  }

  return async (args, extra) => {
    const role =
      PROXY_AUTH_ROLES.find(r => r === extra.authInfo?.extra?.role) ?? 'viewer';
    const email = extra.authInfo?.extra?.email;
    if (!hasRole(role, needed)) {
      writeDecisions.add(1, { role, outcome: 'denied' });
      logger.warn({ email, role, tool: name }, 'Proxy auth: MCP tool denied');
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `Your role (${role}) cannot run ${name}; it requires ${needed}.`,
          },
        ],
      };
    }
    writeDecisions.add(1, { role, outcome: 'allowed' });
    logger.info({ email, role, tool: name }, 'Proxy auth: MCP write');
    return handler(args, extra);
  };
}
