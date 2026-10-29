# @hyperdx/sso

Fork-owned OIDC sign-in and roles for HyperDX. HyperDX talks to one OIDC
provider, [Dex](https://dexidp.io), which fronts GitHub and Google. Users get
real per-user accounts in HyperDX, plus viewer/member/admin roles from their IdP
groups. Upstream HyperDX OSS has neither.

## Layout and upstream merges

SSO code lives in files upstream never touches:

| File                           | What                                                                 |
| ------------------------------ | -------------------------------------------------------------------- |
| `packages/sso/`                | This package: OIDC flow, role guard, MCP tool guard, `SsoRole` model |
| `packages/api/src/sso.ts`      | Wires the package to the API's models, config and logger             |
| `packages/app/src/SsoGate.tsx` | Replaces the password login/register page with "Sign in with SSO"    |
| `charts/clickstack-sso/`       | Helm chart: ClickStack + Dex, pinned to the image                    |

Upstream files carry only these hooks:

| Upstream file                                              | Hook                                                                              |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `packages/api/src/api-app.ts`                              | `import { sso } from './sso'` and `sso.install(app)` after `app.use(defaultCors)` |
| `packages/api/src/mcp/utils/registerTool.ts`               | Wraps the handler in `sso.guardMcpTool(name, config.annotations, traced)`         |
| `packages/api/package.json`                                | `"@hyperdx/sso": "workspace:*"`                                                   |
| `packages/app/pages/login/index.tsx`, `pages/register.tsx` | Wrap `<AuthPage>` in `<SsoGate>`                                                  |
| `docker/hyperdx/Dockerfile`                                | Copy, build and ship `packages/sso` next to `common-utils`                        |

If a merge conflicts, it conflicts on one of these lines. Re-apply the hook.

### Syncing an upstream release

```bash
git fetch upstream --tags
git checkout -b claude/sync-2.43.0 main
git merge '@hyperdx/app@2.43.0'       # match the ClickStack chart appVersion
yarn install                          # also rebuilds packages/sso
cd packages/sso && yarn ci:unit
cd ../api && npx tsc --noEmit && yarn ci:unit
```

Then check for new write routes. Any write route not listed in `roles.ts` is
admin-only, so new upstream routes fail closed. Classify them in `VIEWER_WRITES`
or `MEMBER_WRITES` if members or viewers need them:

```bash
git diff ORIG_HEAD -- packages/api/src/routers packages/api/src/api-app.ts
```

Merging `main` triggers "Build SSO image", which pushes the image
`ghcr.io/<owner>/hyperdx:<api version>-sso.<sha>` and the `clickstack-sso` chart
with the same version, pinned to that image.

## How it works

1. `/login` asks `GET /api/sso/config`. When SSO is on, it shows "Sign in with
   SSO" instead of the password form.
2. `GET /api/sso/login` redirects to Dex with state, nonce and PKCE stored in
   the session. Dex shows its GitHub/Google picker.
3. `GET /api/sso/callback` validates the ID token through `openid-client`. It
   requires a verified email and at least one group in `SSO_ALLOWED_GROUPS`,
   then finds or creates the user by email in the single HyperDX team. It starts
   a passport session holding the role, and records the role in the `ssoroles`
   collection for access keys.
4. The role guard runs before every router. A session older than
   `SSO_SESSION_MAX_HOURS` is signed out, so group removals take effect. The
   next sign-in usually completes without a prompt.

Users are matched by email, so accounts created under the old oauth2-proxy setup
keep their dashboards and access keys. Password login, registration and invite
links return 404 while SSO is on.

## Runtime config (HyperDX container)

| Env                            | Default                       | Purpose                                                                                                        |
| ------------------------------ | ----------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `SSO_ENABLED`                  | `false`                       | Master switch.                                                                                                 |
| `SSO_OIDC_ISSUER`              | —                             | Dex issuer URL, e.g. `https://click.topia.io/dex`. The API must reach it too.                                  |
| `SSO_OIDC_CLIENT_ID`           | —                             | Dex static client id.                                                                                          |
| `SSO_OIDC_CLIENT_SECRET`       | —                             | Dex static client secret.                                                                                      |
| `SSO_OIDC_SCOPES`              | `openid email profile groups` |                                                                                                                |
| `SSO_GROUPS_CLAIM`             | `groups`                      | ID token claim with the user's groups.                                                                         |
| `SSO_ALLOWED_GROUPS`           | — (required)                  | Comma-separated. Sign-in needs one of these.                                                                   |
| `SSO_ADMIN_GROUPS`             | empty → everyone admin        | Full access.                                                                                                   |
| `SSO_MEMBER_GROUPS`            | empty                         | May author dashboards, saved searches, alerts, webhooks, pinned filters.                                       |
| `SSO_SESSION_MAX_HOURS`        | `24`                          | Forces a fresh sign-in, which re-reads groups.                                                                 |
| `SSO_ACCESS_KEY_MAX_IDLE_DAYS` | `30`                          | Access keys stop working when their owner hasn't signed in for this long. `0` disables.                        |
| `SSO_DEFAULT_TEAM_NAME`        | `HyperDX`                     | Team created on the first sign-in.                                                                             |
| `FRONTEND_URL`                 | —                             | Public URL. Builds the callback `${FRONTEND_URL}/api/sso/callback`, and is the only `Origin` allowed to write. |

The API refuses to start with `SSO_ENABLED=true` and any required value unset.

Groups are lowercased before comparison. Dex's GitHub connector emits
`org:team-slug`. Its Google connector emits group emails. Both kinds can be
mixed in one list:

```
SSO_ALLOWED_GROUPS=topia-io:devops,topia-io:dev,metaversecloud-com:devops,metaversecloud-com:dev,eng@topia.io
SSO_ADMIN_GROUPS=topia-io:devops,metaversecloud-com:devops,devops@topia.io
SSO_MEMBER_GROUPS=topia-io:dev,metaversecloud-com:dev,eng@topia.io
```

A denied sign-in logs `SSO: sign-in denied, no allowed group` with the groups
Dex sent. Check that log when a group name doesn't match.

## Roles

| Role       | Can                                                                                                          |
| ---------- | ------------------------------------------------------------------------------------------------------------ |
| **admin**  | everything                                                                                                   |
| **member** | viewer + create/edit/delete dashboards, saved searches, alerts, webhooks, pinned filters                     |
| **viewer** | read; run searches/charts (`/clickhouse-proxy`, PromQL, AI assistant); own favorites, onboarding, access key |

Sources, connections, team settings, IaC and connection tests are admin-only.
Non-admin ClickHouse queries are forced to `readonly=2`. The team ingestion key
is stripped from `GET /me` and `GET /team` for non-admins. Browser writes from
another origin are rejected (`Sec-Fetch-Site`, else `Origin`). The UI is
unchanged: non-admins still see edit buttons, and saving returns 403 naming the
required role.

Decisions are logged (`SSO: write`, `SSO: write denied`, `SSO: MCP write`,
`SSO: role changed`) and counted in `hyperdx.sso.write_decisions{role,outcome}`.
Sign-ins are counted in `hyperdx.sso.logins{outcome}`.

### Access keys, API v2 and MCP

`/api/v2/*` and `/mcp` authenticate by personal access key. They take the role
from the key owner's last SSO sign-in (`ssoroles` collection). A key is rejected
with 403 if its owner never signed in through SSO, or not within
`SSO_ACCESS_KEY_MAX_IDLE_DAYS`. Keys whose owners last signed in through
oauth2-proxy stay inactive until that owner signs in once through Dex.

MCP is gated per tool. Tools annotated `readOnlyHint` are open to viewers,
`*_source` tools need admin, and every other write tool needs member.

**Revoking someone:** remove them from the GitHub team or Google group. That
blocks new sign-ins, and their session ends within `SSO_SESSION_MAX_HOURS`. To
cut access immediately, including their access key, delete them in Team
Settings.

## Dex

Dex ships with HyperDX in the
[`clickstack-sso`](../../charts/clickstack-sso/README.md) Helm chart, which also
sets every `SSO_*` value above from one `global.sso` block.

## Development

The API imports the built package. `yarn dev` builds it first (nx `dependsOn` on
the api's `dev` and `dev-task` targets), and the api's `ci:*` targets build it
through `^ci:build`. While editing `src/`, run `yarn workspace @hyperdx/sso dev`
to rebuild on change.

There is deliberately no `postinstall`: the image's
`yarn workspaces focus --production` would run it without TypeScript.

```bash
cd packages/sso
yarn ci:unit       # role guard, login flow, ID token mapping
yarn ci:lint
```
