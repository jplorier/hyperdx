# clickstack-sso

One Helm release with:

- **ClickStack**
  ([`clickstack`](https://github.com/ClickHouse/ClickStack-helm-charts) 3.4.0),
  running this fork's HyperDX image with SSO on.
- **Dex** ([`dex`](https://github.com/dexidp/helm-charts) 0.26.0, image
  v2.46.1), the OIDC provider HyperDX signs in through, with GitHub and Google
  connectors.

It replaces deploying ClickStack and oauth2-proxy separately.

## Install

CI publishes the chart and image with the same version on every push to `main`:

```bash
helm install clickstack oci://ghcr.io/jplorier/charts/clickstack-sso \
  --version 2.42.0-sso.<sha> -f values.yaml
```

The GHCR package `charts/clickstack-sso` starts private, like the image. Make it
public once (Packages → `charts/clickstack-sso` → Package settings → Change
visibility), or give the cluster or Terraform a pull token.

Minimal values:

```yaml
global:
  sso:
    host: click.topia.io
    oidcClientSecret: <openssl rand -hex 32>
    allowedGroups: [topia-io:devops, topia-io:dev, eng@topia.io]
    adminGroups: [topia-io:devops, devops@topia.io]
    memberGroups: [topia-io:dev, eng@topia.io]

sso:
  github:
    clientID: <GitHub OAuth App>
    clientSecret: <GitHub OAuth App>
    orgs:
      - name: topia-io
        teams: [devops, dev]
      - name: metaversecloud-com
        teams: [devops, dev]
  google:
    enabled: true
    clientID: <Google OAuth client>
    clientSecret: <Google OAuth client>
    hostedDomains: [topia.io]
    serviceAccountJSON: <key JSON>
    adminEmail: <workspace admin>@topia.io
  dexIngress:
    className: alb
    annotations:
      alb.ingress.kubernetes.io/group.name: clickstack # same ALB as HyperDX

clickstack:
  hyperdx:
    ingress: { ... } # your existing HyperDX ingress for the same host
```

Everything under `clickstack:` passes through to the ClickStack chart. The chart
fills in `FRONTEND_URL`, the `SSO_*` settings and the HyperDX image.

## External setup

- **GitHub OAuth App:** callback `https://<host>/dex/callback`. The org must
  approve the app if it restricts third-party access.
- **Google OAuth client** (Web application): redirect URI
  `https://<host>/dex/callback`.
- **Google groups:** a Workspace admin creates a service account and grants it
  domain-wide delegation for
  `https://www.googleapis.com/auth/admin.directory.group.readonly`. `adminEmail`
  is the admin it impersonates. Without `serviceAccountJSON`, Google users have
  no groups and can't sign in.

## Notes

- Group names: with `orgs` set, Dex's GitHub connector emits only
  `org:team-slug`, never a bare `org`. Google groups are group email addresses.
- HyperDX fetches Dex's discovery document and tokens from `https://<host>/dex`
  server-side, so the pods must be able to reach the public host.
- Dex and its config Secret have fixed names (`dex`, `dex-config`,
  `dex-google-sa`): one release per namespace.
- Neither chart restarts pods when only its config changes. After an upgrade
  that changes Dex settings, run `kubectl rollout restart deploy/dex`. After
  changing group lists or other `SSO_*` settings, restart the HyperDX
  deployment. A new image tag restarts HyperDX on its own.
- SSO behaviour, roles and access keys: see
  [packages/sso/README.md](../../packages/sso/README.md).
