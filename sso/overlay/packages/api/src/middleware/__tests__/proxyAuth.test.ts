import express from 'express';
import request from 'supertest';

const ADMIN = 'topia-io, topia-io:devops';
const VIEWER = 'topia-io, topia-io:dev';

function buildApp(adminGroups = 'topia-io:devops,metaversecloud-com:devops') {
  let app: express.Express;
  jest.isolateModules(() => {
    process.env.PROXY_AUTH_ENABLED = 'true';
    process.env.PROXY_AUTH_ADMIN_GROUPS = adminGroups;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { proxyAuthRoleGuard } = require('../proxyAuth');
    app = express();
    app.use(proxyAuthRoleGuard);
    app.use((req, res) => {
      res.json({ url: req.url, originalUrl: req.originalUrl });
    });
  });
  return app!;
}

describe('proxyAuthRoleGuard', () => {
  const app = buildApp();

  it('lets admins write', async () => {
    await request(app)
      .delete('/dashboards/123')
      .set('x-forwarded-groups', ADMIN)
      .expect(200);
  });

  it('lets viewers read', async () => {
    await request(app)
      .get('/dashboards')
      .set('x-forwarded-groups', VIEWER)
      .expect(200);
  });

  it.each([
    ['post', '/dashboards'],
    ['patch', '/dashboards/123'],
    ['delete', '/dashboards/123'],
    ['post', '/alerts'],
    ['put', '/sources/123'],
    ['post', '/connections'],
    ['post', '/clickhouse-proxy/test'],
    ['post', '/mcp'],
  ] as const)('denies viewer %s %s', async (method, path) => {
    await request(app)
      [method](path)
      .set('x-forwarded-groups', VIEWER)
      .expect(403);
  });

  it('denies writes when the groups header is missing', async () => {
    await request(app).post('/dashboards').expect(403);
  });

  it.each([
    '/v1/prometheus/query_range',
    '/ai/assistant',
    '/me/onboarding/task',
  ])('allows viewer read-only POST %s', async path => {
    await request(app).post(path).set('x-forwarded-groups', VIEWER).expect(200);
  });

  it('forces readonly=2 on viewer ClickHouse queries', async () => {
    const res = await request(app)
      .post('/clickhouse-proxy/?query_id=1&readonly=0')
      .set('x-forwarded-groups', VIEWER)
      .expect(200);
    const params = new URL(res.body.originalUrl, 'http://x').searchParams;
    expect(params.getAll('readonly')).toEqual(['2']);
    expect(params.get('query_id')).toBe('1');
    expect(res.body.url).toContain('readonly=2');
  });

  it('leaves admin ClickHouse queries untouched', async () => {
    const res = await request(app)
      .post('/clickhouse-proxy/?query_id=1')
      .set('x-forwarded-groups', ADMIN)
      .expect(200);
    expect(res.body.originalUrl).not.toContain('readonly');
  });

  it('is a no-op when no admin groups are configured', async () => {
    await request(buildApp(''))
      .delete('/dashboards/123')
      .set('x-forwarded-groups', VIEWER)
      .expect(200);
  });
});
