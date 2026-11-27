import { eq } from 'drizzle-orm';

import { firewallPolicy } from './schema';

import type { DBExecutor } from '#db/types';
import {
  defaultFirewallPolicy,
  FirewallPolicySchema,
  type FirewallPolicy,
} from '#shared/contracts/firewall';

export class FirewallRepository {
  constructor(
    private readonly db: DBExecutor,
    private readonly interfaceName: string
  ) {}

  async get() {
    const row = await this.db.query.firewallPolicy.findFirst({
      where: eq(firewallPolicy.id, this.interfaceName),
    });
    return row
      ? {
          revision: row.revision,
          policy: FirewallPolicySchema.parse(JSON.parse(row.policy)),
        }
      : { revision: 0, policy: defaultFirewallPolicy() };
  }

  async update(revision: number, policy: FirewallPolicy) {
    const current = await this.get();
    if (current.revision !== revision) {
      return false;
    }
    await this.db
      .insert(firewallPolicy)
      .values({
        id: this.interfaceName,
        revision: revision + 1,
        policy: JSON.stringify(FirewallPolicySchema.parse(policy)),
      })
      .onConflictDoUpdate({
        target: firewallPolicy.id,
        set: { revision: revision + 1, policy: JSON.stringify(policy) },
      });
    return true;
  }
}
