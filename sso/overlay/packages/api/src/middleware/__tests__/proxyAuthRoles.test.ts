import express from 'express';
import request from 'supertest';

const ADMIN = 'topia-io, topia-io:devops';
const MEMBER = 'topia-io, topia-io:dev';
const VIEWER = 'topia-io';

const mockFindUser = jest.fn();
const mockFindRole = jest.fn();
const mockUpsertRole = jest.fn();

jest.mock('@/models/user', () => ({
  __esModule: true,
  default: { findOne: (...args: unknown[]) => mockFindUser(...args) },
}));
jest.mock('@/models/proxyAuthRole', () => ({
  __esModule: true,
  PROXY_AUTH_ROLES: ['viewer', 'member', 'admin'],
  default: {
    findOne: (...args: unknown[]) => mockFindRole(...args),
    findOneAndUpdate: (...args: unknown[]) => mockUpsertRole(...args),
  },
}));

type Roles = typeof import('../proxyAuthRoles');

function load(adminGroups = 'topia-io:devops,metaversecloud-com:devops') {
  let mod: Roles;
  jest.isolateModules(() => {
    process.env.PROXY_AUTH_ENABLED = 'true';
    process.env.PROXY_AUTH_ADMIN_GROUPS = adminGroups;
    process.env.PROXY_AUTH_MEMBER_GROUPS = 'topia-io:dev';
    process.env.PROXY_AUTH_EMAIL_HEADER = 'x-forwarded-email';
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    mod = require('../proxyAuthRoles');
  });
  return mod!;
}

function buildApp(
  adminGroups?: string,
  sessionUser?: { _id: string; email: string },
) {
  const { proxyAuthRoleGuard } = load(adminGroups);
  const app = express();
  app.use((req, _res, next) => {
    // Stands in for passport.session().
    req.user = sessionUser as Express.User | undefined;
    next();
  });
  app.use(proxyAuthRoleGuard);
  app.use((req, res) => {
    res.json({
      url: req.url,
      originalUrl: req.originalUrl,
      user: req.user ?? null,
      auth: (req as { auth?: unknown }).auth ?? null,
    });
  });
  return app;
}

beforeEach(() => {
  mockFindUser.mockReset();
  mockFindRole.mockReset();
  mockUpsertRole.mockReset().mockResolvedValue(null);
});

describe('proxyAuthRoleGuard (session)', () => {
  const app = buildApp();

  it('lets admins write anything', async () => {
    for (const path of ['/dashboards/1', '/sources/1', '/team/member/1']) {
      await request(app)
        .delete(path)
        .set('x-forwarded-groups', ADMIN)
        .expect(200);
    }
  });

  it('lets everyone read', async () => {
    await request(app)
      .get('/sources')
      .set('x-forwarded-groups', VIEWER)
      .expect(200);
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
    await request(app)
      [method](path)
      .set('x-forwarded-groups', MEMBER)
      .expect(200);
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
      .set('x-forwarded-groups', MEMBER)
      .expect(403);
    expect(res.body.message).toContain('requires admin');
  });

  it.each([
    ['post', '/dashboards'],
    ['delete', '/alerts/1'],
    ['put', '/pinned-filters'],
  ] as const)('denies viewers %s %s', async (method, path) => {
    await request(app)
      [method](path)
      .set('x-forwarded-groups', VIEWER)
      .expect(403);
  });

  it('treats a missing groups header as viewer', async () => {
    await request(app).post('/dashboards').expect(403);
  });

  it.each([
    ['post', '/v1/prometheus/query_range'],
    ['post', '/ai/assistant'],
    ['post', '/me/onboarding/task'],
    ['patch', '/me/onboarding/dismiss'],
    ['patch', '/me/accessKey'],
    ['put', '/favorites'],
  ] as const)('lets viewers %s %s', async (method, path) => {
    await request(app)
      [method](path)
      .set('x-forwarded-groups', VIEWER)
      .expect(200);
  });

  it.each([VIEWER, MEMBER])(
    'forces readonly=2 on non-admin ClickHouse queries (%s)',
    async groups => {
      const res = await request(app)
        .post('/clickhouse-proxy/?query_id=1&readonly=0')
        .set('x-forwarded-groups', groups)
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
      .set('x-forwarded-groups', ADMIN)
      .expect(200);
    expect(res.body.originalUrl).not.toContain('readonly');
  });

  it('lets everyone write when no admin groups are configured', async () => {
    await request(buildApp(''))
      .delete('/sources/1')
      .set('x-forwarded-groups', VIEWER)
      .expect(200);
  });
});

describe('proxyAuthRoleGuard (session identity)', () => {
  const user = { _id: 'u1', email: 'dev@topia.io' };

  it('records the role of the signed-in user once', async () => {
    const app = buildApp(undefined, user);
    for (let i = 0; i < 2; i++) {
      await request(app)
        .get('/dashboards')
        .set('x-forwarded-email', 'Dev@topia.io')
        .set('x-forwarded-groups', MEMBER)
        .expect(200);
    }
    expect(mockUpsertRole).toHaveBeenCalledTimes(1);
    expect(mockUpsertRole.mock.calls[0][0]).toEqual({ user: 'u1' });
    expect(mockUpsertRole.mock.calls[0][1]).toMatchObject({
      role: 'member',
      groups: ['topia-io', 'topia-io:dev'],
    });
  });

  it('drops a session that belongs to another account', async () => {
    const res = await request(buildApp(undefined, user))
      .get('/dashboards')
      .set('x-forwarded-email', 'someone-else@topia.io')
      .set('x-forwarded-groups', ADMIN)
      .expect(200);
    expect(res.body.user).toBeNull();
    expect(mockUpsertRole).not.toHaveBeenCalled();
  });
});

describe('proxyAuthRoleGuard (access key)', () => {
  const app = buildApp();
  const keyUser = { _id: 'u2', email: 'bot@topia.io' };

  function withRole(role: string, lastSeenAt = new Date()) {
    mockFindUser.mockResolvedValue(keyUser);
    mockFindRole.mockResolvedValue({ role, lastSeenAt });
  }

  it('passes unknown keys through for validateUserAccessKey to reject', async () => {
    mockFindUser.mockResolvedValue(null);
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

  it('ignores group headers on access-key requests', async () => {
    withRole('viewer');
    await request(app)
      .post('/api/v2/sources')
      .set('authorization', 'Bearer k')
      .set('x-forwarded-groups', ADMIN)
      .expect(403);
  });

  it('rejects keys whose owner never signed in', async () => {
    mockFindUser.mockResolvedValue(keyUser);
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
  const { guardMcpTool } = load();
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
