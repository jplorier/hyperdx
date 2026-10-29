import { useRouter } from 'next/router';
import { NextSeo } from 'next-seo';
import { Alert, Button, Paper, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';

import { useBrandDisplayName, usePageTitle } from './theme/ThemeProvider';
import { hdxServer } from './api';
import { IS_LOCAL_MODE } from './config';
import LandingHeader from './LandingHeader';

// Fork-owned: replaces the password login and register pages with the OIDC
// sign-in when the API runs with SSO_ENABLED (see packages/sso).
export default function SsoGate({ children }: { children: React.ReactNode }) {
  const { data, isLoading } = useQuery({
    queryKey: ['sso-config'],
    queryFn: () =>
      IS_LOCAL_MODE
        ? { enabled: false }
        : hdxServer('sso/config').json<{ enabled: boolean }>(),
  });

  if (isLoading) {
    return null;
  }
  return data?.enabled ? <SsoLogin /> : children;
}

function SsoLogin() {
  const brandName = useBrandDisplayName();
  const title = usePageTitle('Login');
  const { err } = useRouter().query;

  return (
    <div className="AuthPage">
      <NextSeo title={title} />
      <LandingHeader activeKey="/login" fixed />
      <div className="d-flex justify-content-center align-items-center vh-100">
        <Stack w="26rem" gap="xl">
          <Text ta="center" fz="lg">
            Login to <span className="text-brand fw-bold">{brandName}</span>
          </Text>
          <Paper p={34} shadow="md" radius="md">
            <Button
              component="a"
              href="/api/sso/login"
              variant="primary"
              size="md"
              fullWidth
              data-test-id="sso-login"
            >
              Sign in with SSO
            </Button>
          </Paper>
          {err != null && (
            <Alert variant="danger" data-test-id="auth-error-msg">
              {err === 'ssoNotAllowed'
                ? 'Your account is not in a group allowed to use this app.'
                : 'Sign-in failed, please try again.'}
            </Alert>
          )}
        </Stack>
      </div>
    </div>
  );
}
