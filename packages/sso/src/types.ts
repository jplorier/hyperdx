import type { SsoRoleName } from './model';
import type { PendingLogin } from './oidc';

export interface SsoUser {
  _id: { toString(): string };
  email: string;
}

type LogFn = (obj: object, msg: string) => void;

export interface SsoDeps {
  logger: { info: LogFn; warn: LogFn; error: LogFn };
  // Public URL of the app. Builds the OIDC callback URL and is the only
  // Origin accepted for browser writes.
  frontendUrl: string;
  // Where the browser lands after signing in or failing to.
  redirectBase: string;
  findOrCreateUser(identity: {
    email: string;
    name: string;
  }): Promise<SsoUser & Express.User>;
  findUserByAccessKey(key: string): Promise<SsoUser | null>;
}

export interface SsoSession {
  userId: string;
  role: SsoRoleName;
  groups: string[];
  verifiedAt: number;
}

declare module 'express-session' {
  interface SessionData {
    sso?: SsoSession;
    ssoPending?: PendingLogin;
  }
}

export function isSsoUser(user: unknown): user is SsoUser {
  return (
    typeof user === 'object' &&
    user !== null &&
    '_id' in user &&
    'email' in user
  );
}
