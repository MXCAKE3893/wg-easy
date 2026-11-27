import z from 'zod';
import { isIP } from 'is-ip';
import isCidr from 'is-cidr';

const id = z.int().positive();
const key = z.string().regex(/^[a-zA-Z0-9_-]{1,32}$/);
const prefix = z
  .string()
  .max(64)
  .refine((v) => isIP(v) || !!isCidr(v), {
    message: 'IP address or CIDR required',
  });
const ports = z
  .string()
  .regex(/^([1-9]\d{0,4})(?:-([1-9]\d{0,4}))?$/)
  .refine((v) => {
    const [start, end = start] = v.split('-').map(Number);
    return start! <= end! && end! <= 65535;
  });

export const FirewallRuleSchema = z
  .strictObject({
    id: key,
    name: z.string().trim().min(1).max(100),
    enabled: z.boolean(),
    scope: z.enum(['global', 'group', 'peer']),
    peerId: id.nullable(),
    groupId: key.nullable(),
    priority: z.int().min(0).max(10000),
    action: z.enum(['ALLOW', 'DENY']),
    destination: z.enum([
      'any',
      'peers',
      'server',
      'lan',
      'docker',
      'internet',
      'cidr',
    ]),
    targetPeerId: id.nullable(),
    cidr: prefix.nullable(),
    family: z.enum(['both', 'ipv4', 'ipv6']),
    protocol: z.enum(['any', 'tcp', 'udp', 'icmp']),
    ports: ports.nullable(),
    log: z.boolean(),
  })
  .superRefine((rule, ctx) => {
    const invalid = (message: string) =>
      ctx.addIssue({ code: 'custom', message });
    if ((rule.scope === 'peer') !== (rule.peerId !== null)) {
      invalid('Peer scope requires only peerId');
    }
    if ((rule.scope === 'group') !== (rule.groupId !== null)) {
      invalid('Group scope requires only groupId');
    }
    if ((rule.destination === 'cidr') !== (rule.cidr !== null)) {
      invalid('CIDR destination requires only cidr');
    }
    if (rule.targetPeerId !== null && rule.destination !== 'peers') {
      invalid('Target peer requires peers destination');
    }
    if (
      rule.ports !== null &&
      rule.protocol !== 'tcp' &&
      rule.protocol !== 'udp'
    ) {
      invalid('Ports require TCP or UDP');
    }
    if (
      rule.cidr &&
      rule.family !== 'both' &&
      rule.cidr.includes(':') !== (rule.family === 'ipv6')
    ) {
      invalid('CIDR address family mismatch');
    }
  });

export const FirewallPolicySchema = z
  .strictObject({
    enabled: z.boolean(),
    groups: z
      .array(
        z.strictObject({
          id: key,
          name: z.string().trim().min(1).max(100),
          peerIds: z.array(id).max(1000),
        })
      )
      .max(100),
    lanCidrs: z.array(prefix).max(100),
    dockerCidrs: z.array(prefix).max(100),
    logDefaultDeny: z.boolean(),
    alerts: z.strictObject({
      connections: z.boolean(),
      deniedTraffic: z.boolean(),
      failures: z.boolean(),
      denyThreshold: z.int().min(1).max(10000),
      webhookUrl: z
        .string()
        .trim()
        .max(2048)
        .refine(
          (value) => {
            try {
              const url = new URL(value);
              return (
                url.protocol === 'https:' && !url.username && !url.password
              );
            } catch {
              return false;
            }
          },
          {
            message:
              'Valid HTTPS webhook URL required (no embedded credentials)',
          }
        )
        .nullable()
        .default(null),
    }),
    rules: z.array(FirewallRuleSchema).max(500),
  })
  .superRefine((policy, ctx) => {
    const groups = new Set(policy.groups.map((group) => group.id));
    if (
      groups.size !== policy.groups.length ||
      new Set(policy.rules.map((rule) => rule.id)).size !== policy.rules.length
    ) {
      ctx.addIssue({
        code: 'custom',
        message: 'Group and rule IDs must be unique',
      });
    }
    for (const rule of policy.rules) {
      if (rule.groupId && !groups.has(rule.groupId)) {
        ctx.addIssue({ code: 'custom', message: 'Unknown group' });
      }
    }
  });

export type FirewallPolicy = z.infer<typeof FirewallPolicySchema>;
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;
export const FirewallUpdateSchema = z.strictObject({
  revision: z.int().nonnegative(),
  policy: FirewallPolicySchema,
});

export function defaultFirewallPolicy(): FirewallPolicy {
  return {
    enabled: false,
    groups: [],
    lanCidrs: [
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      '169.254.0.0/16',
      '127.0.0.0/8',
      'fc00::/7',
      'fe80::/10',
    ],
    dockerCidrs: [],
    logDefaultDeny: true,
    alerts: {
      connections: true,
      deniedTraffic: true,
      failures: true,
      denyThreshold: 20,
      webhookUrl: null,
    },
    rules: [],
  };
}
