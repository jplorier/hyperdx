import express from 'express';
import request from 'supertest';

import type { SsoDeps } from '../types';

const mockFindRole = jest.fn();
const mockFindUserByAccessKey = jest.fn();

jest.mock('../model', () => ({
  __esModule: true,
  SSO_ROLES: ['viewer', 'member', 'admin'],
  default: { findOne: (...args: unknown[]) => mockFindRole(...args) },
}));

type Roles = typeof import('../roles');

const deps: SsoDeps = {
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
  frontendUrl: 'https://click.topia.io',
  redirectBase: 'https://click.topia.io',
  findOrCreateUser: jest.fn(),
  findUserByAccessKey: (...args) => mockFindUserByAccessKey(...args),
};

function load(adminGroups = 'topia-io:devops,ops@topia.io') {
  let mod: Roles;
  jest.isolateModules(() => {
    process.env.SSO_ENABLED = 'true';
    process.env.SSO_ADMIN_GROUPS = adminGroups;
    process.env.SSO_MEMBER_GROUPS = 'topia-io:dev';
    process.env.SSO_ALLOWED_GROUPS = 'topia-io';
    process.env.SSO_SESSION_MAX_HOURS = '24';
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    mod = require('../roles');
  });
  return mod!;
}

const user = { _id: 'u1', email: 'dev@topia.io' };

// Stands in for express-session + passport. `x-test-role` is the role set at
// sign-in; `x-test-verified-ago` its age in hours; `x-test-session-user`
// overrides whose session it is.
function buildApp() {
  const app = express();
  app.use((req, _res, next) => {
    const role = req.headers['x-test-role'];
    const r = req as any;
    r.user = role ? user : undefined;
    r.session = role
      ? {
          sso: {
            userId: req.headers['x-test-session-user'] ?? user._id,
            role,
            groups: [],
            verifiedAt:
              Date.now() -
              Number(req.headers['x-test-verified-ago'] ?? 0) * 3600 * 1000,
          },
        }
      : {};
    r.logout = (cb: (err?: unknown) => void) => {
      r.user = null;
      cb();
    };
    next();
  });
  app.use(load().createRoleGuard(deps));
  app.use((req, res) => {
    res.json({
      url: req.url,
      originalUrl: req.originalUrl,
      user: req.user ?? null,
      auth: (req as { auth?: unknown }).auth ?? null,
      apiKey: 'ingest',
      team: { name: 'HyperDX', apiKey: 'ingest', hookId: 'hook' },
    });
  });
  return app;
}

beforeEach(() => {
  mockFindRole.mockReset();
  mockFindUserByAccessKey.mockReset();
});

describe('roleForGroups / isAllowed', () => {
  const { roleForGroups, isAllowed } = load();

  it.each([
    [['topia-io', 'topia-io:devops'], 'admin'],
    [['ops@topia.io'], 'admin'],
    [['topia-io', 'topia-io:dev'], 'member'],
    [['topia-io'], 'viewer'],
  ])('%j -> %s', (groups, role) => {
    expect(roleForGroups(groups)).toBe(role);
  });

  it('makes everyone admin when no admin groups are configured', () => {
    expect(load('').roleForGroups(['topia-io'])).toBe('admin');
  });

  it('requires an allowed group', () => {
    expect(isAllowed(['topia-io'])).toBe(true);
    expect(isAllowed(['other-org'])).toBe(false);
  });
});

describe('ssoRoleGuard (session)', () => {
  const app = buildApp();

  it('lets admins write anything', async () => {
    for (const path of ['/dashboards/1', '/sources/1', '/team/member/1']) {
      await request(app).delete(path).set('x-test-role', 'admin').expect(200);
    }
  });

  it('lets everyone read', async () => {
    await request(app).get('/sources').set('x-test-role', 'viewer').expect(200);
  });

  it.each([
    ['post', '/dashboards'],
    ['patch', '/dashboards/1'],
    ['delete', '/saved-search/1'],
    ['post', '/alerts'],
    ['post', '/alerts/1/silenced'],
    ['put', '/webhooks/1'],
    ['post', '/webhooks/test'],
    ['put', '/pinned-filters'],
  ] as const)('lets members %s %s', async (method, path) => {
    await request(app)[method](path).set('x-test-role', 'member').expect(200);
  });

  it.each([
    ['put', '/sources/1'],
    ['post', '/connections'],
    ['patch', '/team/name'],
    ['delete', '/team/member/1'],
    ['post', '/clickhouse-proxy/test'],
    ['post', '/iac/apply'],
  ] as const)('denies members %s %s', async (method, path) => {
    const res = await request(app)
      [method](path)
      .set('x-test-role', 'member')
      .expect(403);
    expect(res.body.message).toContain('requires admin');
  });

  it.each([
    ['post', '/dashboards'],
    ['delete', '/alerts/1'],
    ['put', '/pinned-filters'],
  ] as const)('denies viewers %s %s', async (method, path) => {
    await request(app)[method](path).set('x-test-role', 'viewer').expect(403);
  });

  it.each([
    ['post', '/v1/prometheus/query_range'],
    ['post', '/ai/assistant'],
    ['post', '/me/onboarding/task'],
    ['patch', '/me/onboarding/dismiss'],
    ['patch', '/me/accessKey'],
    ['put', '/favorites'],
  ] as const)('lets viewers %s %s', async (method, path) => {
    await request(app)[method](path).set('x-test-role', 'viewer').expect(200);
  });

  it.each(['viewer', 'member'])(
    'forces readonly=2 on non-admin ClickHouse queries (%s)',
    async role => {
      const res = await request(app)
        .post('/clickhouse-proxy/?query_id=1&readonly=0')
        .set('x-test-role', role)
        .expect(200);
      const params = new URL(res.body.originalUrl, 'http://x').searchParams;
      expect(params.getAll('readonly')).toEqual(['2']);
      expect(params.get('query_id')).toBe('1');
      expect(res.body.url).toContain('readonly=2');
    },
  );

  it('leaves admin ClickHouse queries untouched', async () => {
    const res = await request(app)
      .post('/clickhouse-proxy/?query_id=1')
      .set('x-test-role', 'admin')
      .expect(200);
    expect(res.body.originalUrl).not.toContain('readonly');
  });

  it('passes unauthenticated requests through to isUserAuthenticated', async () => {
    const res = await request(app).post('/dashboards').expect(200);
    expect(res.body.user).toBeNull();
  });

  it('signs out a session whose sign-in is older than the max age', async () => {
    const res = await request(app)
      .get('/dashboards')
      .set('x-test-role', 'admin')
      .set('x-test-verified-ago', '25')
      .expect(200);
    expect(res.body.user).toBeNull();
  });

  it('signs out a session whose SSO record is for another user', async () => {
    const res = await request(app)
      .get('/dashboards')
      .set('x-test-role', 'admin')
      .set('x-test-session-user', 'u9')
      .expect(200);
    expect(res.body.user).toBeNull();
  });
});

describe('ssoRoleGuard (hardening)', () => {
  const app = buildApp();

  it.each([
    ['post', '/clickhouse-proxy/TEST', 'viewer'],
    ['post', '/Clickhouse-Proxy/test', 'member'],
    ['put', '/Sources/1', 'member'],
    ['post', '/DASHBOARDS', 'viewer'],
  ] as const)(
    'applies roles to case variant %s %s',
    async (method, path, role) => {
      await request(app)[method](path).set('x-test-role', role).expect(403);
    },
  );

  it.each([
    [{ 'sec-fetch-site': 'cross-site' }],
    [{ 'sec-fetch-site': 'same-site' }],
    [{ origin: 'https://evil.example' }],
  ])('blocks cross-site writes %j', async headers => {
    await request(app)
      .post('/alerts/1/silenced')
      .set('x-test-role', 'admin')
      .set(headers)
      .expect(403);
  });

  it.each([
    [{ 'sec-fetch-site': 'same-origin' }],
    [{ origin: 'https://click.topia.io' }],
    [{}],
  ])('allows same-origin and non-browser writes %j', async headers => {
    await request(app)
      .post('/alerts/1/silenced')
      .set('x-test-role', 'admin')
      .set(headers)
      .expect(200);
  });

  it.each(['/me', '/team'])(
    'hides the ingestion key from non-admins on GET %s',
    async path => {
      for (const role of ['viewer', 'member']) {
        const res = await request(app)
          .get(path)
          .set('x-test-role', role)
          .expect(200);
        expect(res.body.apiKey).toBeUndefined();
        expect(res.body.team).toEqual({ name: 'HyperDX' });
      }
      const admin = await request(app)
        .get(path)
        .set('x-test-role', 'admin')
        .expect(200);
      expect(admin.body.team.apiKey).toBe('ingest');
    },
  );

  it.each([
    '/login/password',
    '/register/password',
    '/team/setup/abc',
    '/Login/Password',
  ])('disables password auth route %s', async path => {
    await request(app).post(path).set('x-test-role', 'admin').expect(404);
  });
});

describe('ssoRoleGuard (access key)', () => {
  const app = buildApp();
  const keyUser = { _id: 'u2', email: 'bot@topia.io' };

  function withRole(role: string, lastSeenAt = new Date()) {
    mockFindUserByAccessKey.mockResolvedValue(keyUser);
    mockFindRole.mockResolvedValue({ role, lastSeenAt });
  }

  it('passes unknown keys through for validateUserAccessKey to reject', async () => {
    mockFindUserByAccessKey.mockResolvedValue(null);
    await request(app)
      .post('/api/v2/dashboards')
      .set('authorization', 'Bearer nope')
      .expect(200);
    expect(mockFindRole).not.toHaveBeenCalled();
  });

  it('lets viewers query', async () => {
    withRole('viewer');
    await request(app)
      .post('/api/v2/search')
      .set('authorization', 'Bearer k')
      .expect(200);
    await request(app)
      .post('/api/v2/dashboards')
      .set('authorization', 'Bearer k')
      .expect(403);
  });

  it('lets members write content but not sources', async () => {
    withRole('member');
    await request(app)
      .put('/api/v2/dashboards/1')
      .set('authorization', 'Bearer k')
      .expect(200);
    await request(app)
      .post('/api/v2/sources')
      .set('authorization', 'Bearer k')
      .expect(403);
  });

  it('rejects keys whose owner never signed in', async () => {
    mockFindUserByAccessKey.mockResolvedValue(keyUser);
    mockFindRole.mockResolvedValue(null);
    const res = await request(app)
      .get('/api/v2/dashboards')
      .set('authorization', 'Bearer k')
      .expect(403);
    expect(res.body.message).toContain('inactive');
  });

  it('rejects keys whose owner has not signed in recently', async () => {
    withRole('admin', new Date(Date.now() - 31 * 24 * 60 * 60 * 1000));
    await request(app)
      .get('/api/v2/dashboards')
      .set('authorization', 'Bearer k')
      .expect(403);
  });

  it('passes the role to MCP tool handlers', async () => {
    withRole('member');
    const res = await request(app)
      .post('/mcp')
      .set('authorization', 'Bearer k')
      .expect(200);
    expect(res.body.auth).toMatchObject({
      clientId: 'u2',
      extra: { role: 'member', email: 'bot@topia.io' },
    });
  });
});

describe('guardMcpTool', () => {
  const guardMcpTool = load().createMcpToolGuard(deps);
  const ok = { content: [{ type: 'text' as const, text: 'ok' }] };
  const handler = jest.fn().mockResolvedValue(ok);

  function call(name: string, readOnlyHint: boolean, role: string | undefined) {
    const extra = { authInfo: role ? { extra: { role } } : undefined };
    return guardMcpTool(name, { readOnlyHint }, handler)({}, extra as any);
  }

  it.each([
    ['clickstack_search', true, 'viewer', false],
    ['clickstack_save_dashboard', false, 'viewer', true],
    ['clickstack_save_dashboard', false, undefined, true],
    ['clickstack_save_dashboard', false, 'member', false],
    ['clickstack_save_alert', false, 'member', false],
    ['clickstack_delete_source', false, 'member', true],
    ['clickstack_delete_source', false, 'admin', false],
  ])(
    '%s (readOnly=%s) as %s -> isError=%s',
    async (name, ro, role, isError) => {
      const res = await call(name, ro, role);
      expect(Boolean((res as { isError?: boolean }).isError)).toBe(isError);
    },
  );
});
