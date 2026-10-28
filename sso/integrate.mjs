#!/usr/bin/env node
// Deterministically integrate the SSO overlay into a HyperDX source tree.
//
//   node sso/integrate.mjs <target-dir>
//
// Two steps, both idempotent:
//   1. Copy every file under sso/overlay/ into <target-dir> (new files only,
//      mirroring repo paths) — these never conflict with upstream.
//   2. Anchor-based codemod of packages/api/src/middleware/auth.ts to route
//      unauthenticated requests through the proxy-auth middleware. Fails loudly
//      if the expected anchors are missing (i.e. upstream changed that file's
//      shape) instead of silently producing a broken build.
import { cp, readFile, writeFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const overlayDir = path.join(here, 'overlay');
const target = path.resolve(process.argv[2] || '.');

async function exists(p) {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

// 1) Overlay new files.
await cp(overlayDir, target, { recursive: true });
console.log(`[sso] copied overlay -> ${target}`);

// 2) Codemod the single auth chokepoint.
const authPath = path.join(target, 'packages/api/src/middleware/auth.ts');
if (!(await exists(authPath))) {
  throw new Error(`[sso] expected file not found: ${authPath}`);
}

let src = await readFile(authPath, 'utf8');

if (src.includes('./proxyAuth')) {
  console.log('[sso] auth.ts already integrated, skipping codemod');
} else {
  const importAnchor = "import logger from '@/utils/logger';";
  if (!src.includes(importAnchor)) {
    throw new Error('[sso] import anchor not found in auth.ts');
  }
  src = src.replace(
    importAnchor,
    `${importAnchor}\nimport { proxyAuthEnabled, proxyAuthenticate } from './proxyAuth';`,
  );

  // The bare `res.sendStatus(401)` (no `return`) terminating isUserAuthenticated,
  // immediately followed by getNonNullUserWithTeam — unique in this file.
  const branchAnchor =
    '  res.sendStatus(401);\n}\n\nexport function getNonNullUserWithTeam';
  if (!src.includes(branchAnchor)) {
    throw new Error(
      '[sso] branch anchor not found in auth.ts (isUserAuthenticated layout changed)',
    );
  }
  src = src.replace(
    branchAnchor,
    '  if (proxyAuthEnabled()) {\n    return proxyAuthenticate(req, res, next);\n  }\n\n' +
      branchAnchor,
  );

  await writeFile(authPath, src);
  console.log('[sso] patched isUserAuthenticated in auth.ts');
}

console.log('[sso] integration complete');
