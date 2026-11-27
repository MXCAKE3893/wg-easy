import { readValidatedBody } from 'nuxt/server';

import { defineAuthenticatedEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/http/validation';
import { authorize } from '#server/features/authorization';
import { FirewallUpdateSchema } from '#shared/contracts/firewall';
import * as firewall from '#server/features/firewall';

export default defineAuthenticatedEventHandler(async ({ event, user }) => {
  authorize(user, 'admin', 'any');
  const { revision, policy } = await readValidatedBody(
    event,
    validateZod(FirewallUpdateSchema, event)
  );
  await firewall.update(user, revision, policy);
  return { success: true };
});
