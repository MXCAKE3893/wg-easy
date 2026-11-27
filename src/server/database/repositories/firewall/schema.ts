import { sqliteTable, text, int } from 'drizzle-orm/sqlite-core';

import { wgInterface } from '../interface/schema';

export const firewallPolicy = sqliteTable('firewall_policy', {
  id: text()
    .primaryKey()
    .notNull()
    .references(() => wgInterface.name, {
      onUpdate: 'cascade',
      onDelete: 'cascade',
    }),
  revision: int().notNull().default(0),
  policy: text().notNull(),
});
