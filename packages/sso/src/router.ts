import { metrics, trace } from '@opentelemetry/api';
import express from 'express';

import { SSO_ENABLED } from './config';
import SsoRole from './model';
import { finishLogin, startLogin } from './oidc';
import { isAllowed, roleForGroups } from './roles';
import type { SsoDeps, SsoUser } from './types';

const logins = metrics
  .getMeter('hyperdx-sso')
  .createCounter('hyperdx.sso.logins', {
    description: 'SSO sign-in attempts, labeled by outcome.',
  });

export function createSsoRouter({
  logger,
  frontendUrl,
  redirectBase,
  findOrCreateUser,
}: SsoDeps) {
  const router = express.Router();
  // The app proxies /api/* to this server with the prefix stripped.
  const callbackUrl = `${frontendUrl}/api/sso/callback`;

  router.get('/config', (_req, res) => {
    res.json({ enabled: SSO_ENABLED });
  });

  if (!SSO_ENABLED) {
    return router;
  }

  router.get('/login', async (req, res, next) => {
    try {
      const { url, pending } = await startLogin(callbackUrl);
      req.session.ssoPending = pending;
      res.redirect(303, url);
    } catch (err) {
      next(err);
    }
  });

  router.get('/callback', async (req, res) => {
    const pending = req.session.ssoPending;
    delete req.session.ssoPending;
    const fail = (outcome: string, err: string) => {
      logins.add(1, { outcome });
      res.redirect(303, `${redirectBase}/login?err=${err}`);
    };

    if (!pending) {
      logger.warn({}, 'SSO: callback without a pending login');
      return fail('error', 'sso');
    }

    try {
      const search = new URL(req.originalUrl, 'http://localhost').search;
      const identity = await finishLogin(
        new URL(`${callbackUrl}${search}`),
        pending,
      );
      const { email, groups } = identity;

      if (!isAllowed(groups)) {
        logger.warn({ email, groups }, 'SSO: sign-in denied, no allowed group');
        return fail('denied', 'ssoNotAllowed');
      }

      const role = roleForGroups(groups);
      const user: SsoUser & Express.User = await findOrCreateUser(identity);
      const userId = user._id.toString();

      await new Promise<void>((resolve, reject) =>
        req.login(user, err => (err ? reject(err) : resolve())),
      );
      // Set after req.login, which regenerates the session.
      req.session.sso = { userId, role, groups, verifiedAt: Date.now() };

      const old = await SsoRole.findOneAndUpdate(
        { user: user._id },
        { email, role, groups, lastSeenAt: new Date() },
        { upsert: true },
      );
      if (old && old.role !== role) {
        logger.info(
          { email, from: old.role, to: role, groups },
          'SSO: role changed',
        );
      }

      trace.getActiveSpan()?.setAttributes({
        'hyperdx.sso.email': email,
        'hyperdx.sso.role': role,
        'hyperdx.sso.groups': groups,
        'hyperdx.user.id': userId,
      });
      logins.add(1, { outcome: 'success' });
      logger.info(
        { email, role, type: 'user_login', authType: 'sso' },
        'SSO: signed in',
      );
      return res.redirect(303, `${redirectBase}/`);
    } catch (err) {
      logger.error({ err }, 'SSO: sign-in failed');
      return fail('error', 'sso');
    }
  });

  return router;
}
