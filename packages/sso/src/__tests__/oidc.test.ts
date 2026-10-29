const mockClaims = jest.fn();
const mockDiscovery = jest.fn();

jest.mock('openid-client', () => ({
  discovery: (...args: unknown[]) => mockDiscovery(...args),
  authorizationCodeGrant: async () => ({ claims: mockClaims }),
}));

process.env.SSO_OIDC_ISSUER = 'https://dex.topia.io';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { finishLogin }: typeof import('../oidc') = require('../oidc');

const pending = { state: 's', nonce: 'n', codeVerifier: 'v' };
const callback = new URL('https://click.topia.io/api/sso/callback?code=c');

beforeEach(() => {
  mockDiscovery.mockResolvedValue({});
});

it('maps verified email, name and groups from the ID token', async () => {
  mockClaims.mockReturnValue({
    sub: 'x',
    email: 'Dev@Topia.io',
    email_verified: true,
    name: 'Dev',
    groups: ['Topia-IO:DevOps', 'ops@topia.io', 42],
  });
  await expect(finishLogin(callback, pending)).resolves.toEqual({
    email: 'dev@topia.io',
    name: 'Dev',
    groups: ['topia-io:devops', 'ops@topia.io'],
  });
});

it('rejects an unverified email', async () => {
  mockClaims.mockReturnValue({
    sub: 'x',
    email: 'dev@topia.io',
    email_verified: false,
  });
  await expect(finishLogin(callback, pending)).rejects.toThrow(
    'no verified email',
  );
});

it('treats a missing groups claim as no groups', async () => {
  mockClaims.mockReturnValue({ sub: 'x', email: 'dev@topia.io' });
  await expect(finishLogin(callback, pending)).resolves.toMatchObject({
    name: 'dev@topia.io',
    groups: [],
  });
});
