import { defineAuthenticatedEventHandler } from '#server/utils/handler';
import * as firewall from '#server/features/firewall';

export default defineAuthenticatedEventHandler(({ user }) =>
  firewall.get(user)
);
