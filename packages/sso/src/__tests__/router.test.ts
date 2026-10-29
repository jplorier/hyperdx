import express from 'express';
import session from 'express-session';
import request from 'supertest';

import type { SsoDeps } from '../types';

const mockStartLogin = jest.fn();
const mockFinishLogin = jest.fn();
const mockUpsertRole = jest.fn();

jest.mock('../oidc', () => ({
  startLogin: (...args: unknown[]) => mockStartLogin(...args),
  finishLogin: (...args: unknown[]) => mockFinishLogin(...args),
}));
jest.mock('../model', () => ({
  __esModule: true,
  SSO_ROLES: ['viewer', 'member', 'admin'],
  default: {
    findOneAndUpdate: (...args: unknown[]) => mockUpsertRole(...args),
  },
}));

const user = { _id: 'u1', email: 'dev@topia.io' };
const findOrCreateUser = jest.fn();
const deps: SsoDeps = {
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
  frontendUrl: 'https://click.topia.io',
  redirectBase: 'https://click.topia.io',
  findOrCreateUser,
  findUserByAccessKey: jest.fn(),
};

function buildApp(enabled = true) {
  let createSsoRouter: typeof import('../router').createSsoRouter;
  jest.isolateModules(() => {
    process.env.SSO_ENABLED = String(enabled);
    process.env.SSO_ADMIN_GROUPS = 'topia-io:devops';
    process.env.SSO_ALLOWED_GROUPS = 'topia-io';
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    ({ createSsoRouter } = require('../router'));
  });
  const app = express();
  app.use(session({ secret: 'test', resave: false, saveUninitialized: false }));
  app.use((req, _res, next) => {
    // Stands in for passport's req.login.
    (req as any).login = (u: unknown, cb: (err?: unknown) => void) => {
      (req as any).user = u;
      cb();
    };
    next();
  });
  app.use('/sso', createSsoRouter!(deps));
  app.get('/whoami', (req, res) => res.json({ sso: req.session.sso ?? null }));
  return app;
}

const pending = { state: 's', nonce: 'n', codeVerifier: 'v' };

beforeEach(() => {
  jest.clearAllMocks();
  mockStartLogin.mockResolvedValue({ url: 'https://dex/auth?x=1', pending });
  mockUpsertRole.mockResolvedValue(null);
  findOrCreateUser.mockResolvedValue(user);
});

async function startedAgent(app: express.Express) {
  const agent = request.agent(app);
  await agent
    .get('/sso/login')
    .expect(303)
    .expect('location', 'https://dex/auth?x=1');
  expect(mockStartLogin).toHaveBeenCalledWith(
    'https://click.topia.io/api/sso/callback',
  );
  return agent;
}

it('reports whether SSO is enabled', async () => {
  await request(buildApp()).get('/sso/config').expect(200, { enabled: true });
  await request(buildApp(false))
    .get('/sso/config')
    .expect(200, { enabled: false });
  await request(buildApp(false)).get('/sso/login').expect(404);
});

it('signs in an allowed user with the role from their groups', async () => {
  mockFinishLogin.mockResolvedValue({
    email: 'dev@topia.io',
    name: 'Dev',
    groups: ['topia-io', 'topia-io:devops'],
  });
  const agent = await startedAgent(buildApp());

  await agent
    .get('/sso/callback?code=c&state=s')
    .expect(303)
    .expect('location', 'https://click.topia.io/');

  const [callbackUrl, usedPending] = mockFinishLogin.mock.calls[0];
  expect(String(callbackUrl)).toBe(
    'https://click.topia.io/api/sso/callback?code=c&state=s',
  );
  expect(usedPending).toEqual(pending);
  expect(findOrCreateUser).toHaveBeenCalledWith(
    expect.objectContaining({ email: 'dev@topia.io' }),
  );
  expect(mockUpsertRole.mock.calls[0][1]).toMatchObject({
    role: 'admin',
    groups: ['topia-io', 'topia-io:devops'],
  });
  const { body } = await agent.get('/whoami');
  expect(body.sso).toMatchObject({ userId: 'u1', role: 'admin' });
});

it('rejects users outside the allowed groups', async () => {
  mockFinishLogin.mockResolvedValue({
    email: 'x@example.com',
    name: 'X',
    groups: ['other-org'],
  });
  const agent = await startedAgent(buildApp());

  await agent
    .get('/sso/callback?code=c&state=s')
    .expect(303)
    .expect('location', 'https://click.topia.io/login?err=ssoNotAllowed');
  expect(findOrCreateUser).not.toHaveBeenCalled();
});

it('rejects a callback with no login in progress', async () => {
  await request(buildApp())
    .get('/sso/callback?code=c&state=s')
    .expect(303)
    .expect('location', 'https://click.topia.io/login?err=sso');
  expect(mockFinishLogin).not.toHaveBeenCalled();
});

it('does not let a pending login be replayed', async () => {
  mockFinishLogin.mockRejectedValue(new Error('state mismatch'));
  const agent = await startedAgent(buildApp());

  await agent
    .get('/sso/callback?code=c&state=bad')
    .expect('location', 'https://click.topia.io/login?err=sso');
  await agent.get('/sso/callback?code=c&state=s');
  expect(mockFinishLogin).toHaveBeenCalledTimes(1);
});
