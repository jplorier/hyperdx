import { createSso } from '@hyperdx/sso';
import { serializeError } from 'serialize-error';

import * as config from '@/config';
import { createTeam } from '@/controllers/team';
import { findUserByAccessKey } from '@/controllers/user';
import Team from '@/models/team';
import User from '@/models/user';
import { setupTeamDefaults } from '@/setupDefaults';
import logger from '@/utils/logger';

// Fork-owned wiring between @hyperdx/sso and the API's models. Upstream files
// only import `sso` from here, so merges from upstream rarely touch SSO code.

// HyperDX is single-team; the first SSO sign-in bootstraps it. Tolerates a
// concurrent first-login race (createTeam throws if a team already exists).
async function getOrCreateTeam() {
  const existing = await Team.findOne({});
  if (existing) {
    return existing;
  }
  try {
    const team = await createTeam({
      name: process.env.SSO_DEFAULT_TEAM_NAME || 'HyperDX',
      collectorAuthenticationEnforced: true,
    });
    try {
      await setupTeamDefaults(team._id.toString());
    } catch (error) {
      logger.error(
        { err: serializeError(error) },
        'SSO: failed to set up team defaults',
      );
    }
    return team;
  } catch (err) {
    const team = await Team.findOne({});
    if (team) {
      return team;
    }
    throw err;
  }
}

// Identity is asserted by the IdP, so the user has no local password.
async function findOrCreateUser({
  email,
  name,
}: {
  email: string;
  name: string;
}) {
  const user = await User.findOne({ email });
  if (user) {
    return user;
  }
  const team = await getOrCreateTeam();
  try {
    const created = await new User({ email, name, team: team._id }).save();
    logger.info(
      { email, type: 'user_login', authType: 'sso' },
      'SSO: provisioned user',
    );
    return created;
  } catch (err) {
    // Unique-email race: a concurrent sign-in created the user.
    const raced = await User.findOne({ email });
    if (raced) {
      return raced;
    }
    throw err;
  }
}

export const sso = createSso({
  logger,
  frontendUrl: config.FRONTEND_URL,
  redirectBase: config.FRONTEND_REDIRECT_BASE,
  findOrCreateUser,
  findUserByAccessKey: key => findUserByAccessKey(key).exec(),
});
