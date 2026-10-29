import type { Application } from 'express';

import { assertConfig } from './config';
import { createMcpToolGuard, createRoleGuard } from './roles';
import { createSsoRouter } from './router';
import type { SsoDeps } from './types';

export type { SsoDeps, SsoSession, SsoUser } from './types';

export function createSso(deps: SsoDeps) {
  assertConfig();
  return {
    // Mount after the session and passport middleware, before every router.
    install(app: Application) {
      app.use('/sso', createSsoRouter(deps));
      app.use(createRoleGuard(deps));
    },
    guardMcpTool: createMcpToolGuard(deps),
  };
}
