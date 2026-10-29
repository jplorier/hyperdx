# HyperDX proxy-auth SSO overlay

Adds **SSO via a trusting reverse proxy** (oauth2-proxy → GitHub) to the OSS
HyperDX image, *without forking the app's history*. GitHub is wired today; Google
can be added later by fronting oauth2-proxy with Dex (generic OIDC) — the overlay
is provider-agnostic, it only trusts the identity header.

The SSO code lives entirely in this `sso/` directory as an **overlay + codemod**
that is applied onto a chosen upstream tag at build time. Upstream stays a clean
mirror — syncing a new release is just picking a newer tag.

## How it works

HyperDX OSS has a single auth chokepoint: `isUserAuthenticated`
(`packages/api/src/middleware/auth.ts`), which every protected route uses. The
overlay adds one middleware that, when `PROXY_AUTH_ENABLED=true`, reads the
identity header injected by oauth2-proxy, find-or-provisions that user in the
single HyperDX team, and establishes a passport session — giving **real per-user
identity inside HyperDX** and removing the second login prompt.

The header name depends on how oauth2-proxy runs. **In-path / reverse-proxy mode**
(our ALB setup, since ALB has no nginx-style external-auth) passes identity as
`X-Forwarded-Email`; nginx auth_request mode uses `X-Auth-Request-Email`. The
header is configurable via `PROXY_AUTH_EMAIL_HEADER`; in k8-mgmt we set it to
`x-forwarded-email`.

Files:
- `overlay/` — new files, mirrored to repo paths (only `proxyAuth.ts`).
- `integrate.mjs` — copies the overlay and applies an idempotent, anchor-based
  codemod to `auth.ts`. Fails loudly if upstream changed that file's shape.
- `apply.sh` — checks out an upstream tag into a git worktree and runs the codemod.

## Build locally

```bash
sso/apply.sh '@hyperdx/app@2.28.0' build
docker build -f build/docker/hyperdx/Dockerfile --target prod \
  --build-context hyperdx=build/docker/hyperdx \
  --build-context api=build/packages/api \
  --build-context app=build/packages/app \
  --build-arg CODE_VERSION=2.28.0-sso \
  -t ghcr.io/<owner>/hyperdx:2.28.0-sso build
```

## Build in CI

`.github/workflows/sso-image.yml` — run "Build SSO image", pick the upstream tag
matching the ClickStack chart's `appVersion`. Pushes
`ghcr.io/<owner>/hyperdx:<version>-sso`.

**Make the cluster able to pull it — public package (chosen approach).** GHCR
packages publish **private** by default. We make this one **public** so the
cluster needs no pull secret (the image is a build of MIT-licensed OSS). This is
a **one-time, manual, irreversible** step (there is no REST API for it):

1. GitHub profile → **Packages** → open `hyperdx`.
2. Gear icon (**Package settings**) → **Danger Zone** → **Change visibility** → **Public**.
3. Confirm by typing the package name. *(Once public it cannot be made private again.)*

With the package public, leave `clickstack_sso.ghcr_username` / `ghcr_pull_token`
empty in Terraform — `oauth2-proxy.tf` then skips the dockerconfigjson secret and
`global.imagePullSecrets` entirely.

> Fallback if it must stay private: a fine-grained PAT (`packages: read`) on a bot
> account, set as `ghcr_username` + `ghcr_pull_token`. Avoid a GitHub App here —
> its installation tokens expire hourly and a static imagePullSecret can't use them
> without a refresh controller.

## Runtime config (set on the HyperDX container)

| Env | Code default | k8-mgmt sets | Purpose |
|-----|---------|---------|---------|
| `PROXY_AUTH_ENABLED` | `false` | `true` | Master switch. |
| `PROXY_AUTH_EMAIL_HEADER` | `x-auth-request-email` | `x-forwarded-email` | Identity header (in-path mode → `x-forwarded-email`). |
| `PROXY_AUTH_NAME_HEADER` | `x-auth-request-preferred-username` | `x-forwarded-preferred-username` | Display name (optional). |
| `PROXY_AUTH_DEFAULT_TEAM_NAME` | `HyperDX` | (default) | Team created on first login. |
| `PROXY_AUTH_GROUPS_HEADER` | `x-forwarded-groups` | (default) | Groups header (oauth2-proxy GitHub: `org`, `org:team`). |
| `PROXY_AUTH_ADMIN_GROUPS` | (empty → roles off) | `topia-io:devops,metaversecloud-com:devops` | Comma-separated groups with full access. |

### Roles

HyperDX OSS has no RBAC; the overlay adds two roles, enforced app-wide by
`proxyAuthRoleGuard` (mounted before every router):

- **admin** — any user in `PROXY_AUTH_ADMIN_GROUPS`: full access.
- **viewer** — everyone else: all `GET`s plus read-only `POST`s (search/charts via
  `/clickhouse-proxy`, `/v1/prometheus/query*`, `/ai/assistant`,
  `/me/onboarding/*`). Every other write returns 403. Viewer ClickHouse queries
  are forced to `readonly=2`, so raw SQL through the proxy cannot modify data.

The UI is unchanged: viewers still see edit buttons, but saving fails. On an
upstream upgrade, re-check new `POST` routes viewers need and run
`yarn ci:unit src/middleware/__tests__/proxyAuth.test.ts` in the integrated tree.

> **Security:** only enable when HyperDX is reachable *exclusively* through
> oauth2-proxy, and the proxy strips client-supplied copies of these headers.
> Otherwise the identity header can be spoofed. oauth2-proxy strips inbound
> `X-Forwarded-*` / `X-Auth-Request-*` before setting its own, so this holds as
> long as nothing else can reach the app port directly.

## Deploy via Terraform (k8-mgmt)

In the infra-terraform repo, `k8-mgmt/` wires this up:

- **`oauth2-proxy.tf`** — deploys oauth2-proxy (chart `oauth2-proxy/oauth2-proxy`
  v10.7.0) **in-path** on the public ALB for `click.topia.io`, authenticating
  against GitHub restricted to the configured `org:team` list and reverse-proxying
  to `clickstack-app:3000`. When SSO is on, the ClickStack chart's own ingress is
  disabled so only oauth2-proxy claims the host.
- **`clickstack.tf`** — overrides `hyperdx.deployment.image` to the fork image,
  sets the `PROXY_AUTH_*` env (incl. `PROXY_AUTH_EMAIL_HEADER=x-forwarded-email`),
  and wires `global.imagePullSecrets` only when a private-registry token is given.
- **`variables.tf`** — a **separate, `sensitive = true`** variable `clickstack_sso`,
  intentionally **NOT nested** inside `var.clickstack`: the latter is referenced at
  many `count` / `version` / `namespace` sites that need plan-readable
  (non-sensitive) values, so folding secrets in would force `nonsensitive()` across
  all of them.

Example tfvars (package made public → no GHCR credentials needed):

```hcl
clickstack_sso = {
  enabled              = true
  github_client_id     = "<from GitHub OAuth App>"
  github_client_secret = "<from GitHub OAuth App>"
  cookie_secret        = "<openssl rand -base64 32 | tr -- '+/' '-_'>"
  image_repository     = "ghcr.io/<owner>/hyperdx"
  image_tag            = "2.28.0-sso"
  # ghcr_username / ghcr_pull_token omitted → public package
  # allowed_github_teams defaults to topia-io/metaversecloud-com :devops/:dev
}
```

Create the GitHub OAuth App at https://github.com/settings/developers with
callback `https://click.topia.io/oauth2/callback`.

**Go-live order:** build image (CI) → make package public → create OAuth App →
set tfvars → apply.

## Syncing a new upstream release

1. Pick the new `@hyperdx/app@<x.y.z>` tag (match the ClickStack chart `appVersion`).
2. Run the workflow with that tag. If `integrate.mjs` errors on a missing anchor,
   upstream reshaped `isUserAuthenticated` — update the anchors in `integrate.mjs`.
3. Point the chart at the new image tag and upgrade chart + image together.
