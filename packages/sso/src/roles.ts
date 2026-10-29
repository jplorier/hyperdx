import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { ToolCallback } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { metrics } from '@opentelemetry/api';
import type { NextFunction, Request, Response } from 'express';
import type { AnyZodObject } from 'zod';

import {
  ACCESS_KEY_MAX_IDLE_MS,
  ADMIN_GROUPS,
  ALLOWED_GROUPS,
  MEMBER_GROUPS,
  SESSION_MAX_AGE_MS,
  SSO_ENABLED,
} from './config';
import SsoRole, { SSO_ROLES, type SsoRoleName } from './model';
import { isSsoUser, type SsoDeps } from './types';

// Routers authenticated by access key (validateUserAccessKey). They have no
// session, so the role comes from the key owner's last SSO sign-in.
const ACCESS_KEY_PATH = /^\/(mcp|api\/v2)(\/|$)/;

const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

// Path patterns below are matched against the lowercased path, so they must be
// written in lowercase.

// Non-GET routes that only read data or touch the caller's own state.
// /mcp is gated per tool by guardMcpTool.
const VIEWER_WRITES = [
  /^\/clickhouse-proxy\/(?!test(\/|$))/,
  /^\/v1\/prometheus\/query/,
  /^\/ai\/assistant$/,
  /^\/me\/(onboarding\/|accesskey$)/,
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

// Password sign-in and invites bypass the IdP, so they are switched off.
const PASSWORD_AUTH_PATH =
  /^\/(login\/password|register\/password|team\/setup\/)/;

// Responses that embed the team ingestion key, which lets anyone write
// telemetry, so only admins receive it.
const TEAM_KEY_PATH = /^\/(me|team)\/?$/;

const writeDecisions = metrics
  .getMeter('hyperdx-sso')
  .createCounter('hyperdx.sso.write_decisions', {
    description:
      'Writes (HTTP and MCP tool calls) checked against SSO roles, ' +
      'labeled by caller role and outcome (allowed/denied).',
  });

export function hasRole(role: SsoRoleName, needed: SsoRoleName) {
  return SSO_ROLES.indexOf(role) >= SSO_ROLES.indexOf(needed);
}

export function isAllowed(groups: string[]) {
  return groups.some(g => ALLOWED_GROUPS.includes(g));
}

export function roleForGroups(groups: string[]): SsoRoleName {
  if (ADMIN_GROUPS.length === 0 || groups.some(g => ADMIN_GROUPS.includes(g))) {
    return 'admin';
  }
  return groups.some(g => MEMBER_GROUPS.includes(g)) ? 'member' : 'viewer';
}

function requiredRole(method: string, path: string): SsoRoleName {
  if (
    SAFE_METHODS.includes(method) ||
    VIEWER_WRITES.some(re => re.test(path))
  ) {
    return 'viewer';
  }
  return MEMBER_WRITES.some(re => re.test(path)) ? 'member' : 'admin';
}

function headerValue(req: Request, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

function withoutIngestionKey(body: unknown) {
  const data = JSON.parse(JSON.stringify(body ?? null));
  for (const team of [data, data?.team]) {
    if (team && typeof team === 'object') {
      delete team.apiKey;
      delete team.hookId;
    }
  }
  return data;
}

function logout(req: Request) {
  return new Promise<void>((resolve, reject) =>
    req.logout(err => (err ? reject(err) : resolve())),
  );
}

// App-level role guard. Viewers may only read; members may also author
// shared content; admins pass. Non-admin ClickHouse queries are forced to
// readonly=2 so raw SQL sent through the proxy cannot modify data either
// (ClickHouse rejects raising it back).
export function createRoleGuard({
  logger,
  frontendUrl,
  findUserByAccessKey,
}: SsoDeps) {
  // Unset in some environments (tests, local mode); then any Origin counts as
  // cross-site.
  const frontendOrigin = (() => {
    try {
      return new URL(frontendUrl).origin;
    } catch {
      return undefined;
    }
  })();

  // The session cookie is SameSite=Lax, which still lets sibling subdomains
  // post with it. Browsers label every request with Sec-Fetch-Site; Origin
  // covers the ones that don't.
  function isCrossSite(req: Request) {
    const site = headerValue(req, 'sec-fetch-site');
    if (site) {
      return site !== 'same-origin' && site !== 'none';
    }
    const origin = headerValue(req, 'origin');
    return !!origin && origin !== frontendOrigin;
  }

  return async function ssoRoleGuard(
    req: Request,
    res: Response,
    next: NextFunction,
  ) {
    if (!SSO_ENABLED) {
      return next();
    }

    // Express matches routes case-insensitively, so every check below must too.
    const path = req.path.toLowerCase();

    if (PASSWORD_AUTH_PATH.test(path)) {
      return res.sendStatus(404);
    }

    try {
      let role: SsoRoleName;
      let email: string | undefined;

      if (ACCESS_KEY_PATH.test(path)) {
        const key = req.headers.authorization?.split('Bearer ')[1];
        const user = key ? await findUserByAccessKey(key) : null;
        if (!key || !user) {
          // validateUserAccessKey answers 401.
          return next();
        }
        const record = await SsoRole.findOne({ user: user._id });
        if (
          !record ||
          (ACCESS_KEY_MAX_IDLE_MS > 0 &&
            Date.now() - record.lastSeenAt.getTime() > ACCESS_KEY_MAX_IDLE_MS)
        ) {
          logger.warn(
            { email: user.email, lastSeenAt: record?.lastSeenAt },
            'SSO: access key rejected, no recent sign-in',
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
        Object.assign(req, { auth });
      } else {
        const user = isSsoUser(req.user) ? req.user : undefined;
        if (!user) {
          // Private routes answer 401 in isUserAuthenticated.
          return next();
        }
        const sso = req.session.sso;
        if (
          !sso ||
          sso.userId !== user._id.toString() ||
          Date.now() - sso.verifiedAt > SESSION_MAX_AGE_MS
        ) {
          // A session from password login or a stale sign-in: re-verify
          // with the IdP.
          await logout(req);
          return next();
        }
        role = sso.role;
        email = user.email;

        if (!SAFE_METHODS.includes(req.method) && isCrossSite(req)) {
          logger.warn(
            { method: req.method, path, email, origin: req.headers.origin },
            'SSO: cross-site write blocked',
          );
          return res
            .status(403)
            .json({ message: 'Cross-site request blocked' });
        }
      }

      const needed = requiredRole(req.method, path);
      if (!hasRole(role, needed)) {
        writeDecisions.add(1, { role, outcome: 'denied' });
        logger.warn(
          { method: req.method, path, email, role, needed },
          'SSO: write denied',
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

      if (
        role !== 'admin' &&
        req.method === 'GET' &&
        TEAM_KEY_PATH.test(path)
      ) {
        const json = res.json.bind(res);
        res.json = body => json(withoutIngestionKey(body));
      }

      if (needed !== 'viewer') {
        writeDecisions.add(1, { role, outcome: 'allowed' });
        res.on('finish', () => {
          logger.info(
            { method: req.method, path, email, role, status: res.statusCode },
            'SSO: write',
          );
        });
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };
}

// MCP serves every tool over one POST /mcp, so writes are gated per tool:
// tools not marked read-only need member, source tools need admin. Fails
// closed when the guard resolved no role for the request.
export function createMcpToolGuard({ logger }: SsoDeps) {
  return function guardMcpTool(
    name: string,
    annotations: ToolAnnotations | undefined,
    handler: ToolCallback<AnyZodObject>,
  ): ToolCallback<AnyZodObject> {
    const needed: SsoRoleName = annotations?.readOnlyHint
      ? 'viewer'
      : name.endsWith('_source')
        ? 'admin'
        : 'member';
    if (!SSO_ENABLED || needed === 'viewer') {
      return handler;
    }

    return async (args, extra) => {
      const role =
        SSO_ROLES.find(r => r === extra.authInfo?.extra?.role) ?? 'viewer';
      const email = extra.authInfo?.extra?.email;
      if (!hasRole(role, needed)) {
        writeDecisions.add(1, { role, outcome: 'denied' });
        logger.warn({ email, role, tool: name }, 'SSO: MCP tool denied');
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
      logger.info({ email, role, tool: name }, 'SSO: MCP write');
      return handler(args, extra);
    };
  };
}
