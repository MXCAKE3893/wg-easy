import { describe, expect, test, vi } from 'vitest';

import { databaseFixture } from '../helpers/database';

import {
  compilePolicy,
  policyLogPrefix,
} from '#server/features/firewall/compiler';
import {
  FirewallPolicySchema,
  FirewallRuleSchema,
  defaultFirewallPolicy,
  type FirewallRule,
} from '#shared/contracts/firewall';
import { firewall } from '#server/utils/firewall';
import { exec } from '#server/utils/cmd';
import {
  createAlertDelivery,
  parseFirewallLog,
} from '#server/features/firewall/monitor';
import {
  firewallRuntime,
  recordEvent,
  securityEvents,
} from '#server/features/firewall/runtime';
import { get } from '#server/features/firewall';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { PORT: '51821', DISABLE_IPV6: false, WG_EXECUTABLE: 'wg' },
}));
vi.mock('#server/utils/cmd', () => ({ exec: vi.fn().mockResolvedValue('') }));

const peers = [
  {
    id: 1,
    enabled: true,
    ipv4Address: '10.8.0.2',
    ipv6Address: 'fd00::2',
    serverAllowedIps: ['192.0.2.0/24', '2001:db8::/64'],
  },
  {
    id: 2,
    enabled: true,
    ipv4Address: '10.8.0.3',
    ipv6Address: 'fd00::3',
    serverAllowedIps: [],
  },
  {
    id: 3,
    enabled: false,
    ipv4Address: '10.8.0.4',
    ipv6Address: 'fd00::4',
    serverAllowedIps: [],
  },
];
function rule(data: Partial<FirewallRule> = {}): FirewallRule {
  return {
    id: 'rule',
    name: 'Test',
    enabled: true,
    scope: 'global',
    peerId: null,
    groupId: null,
    priority: 100,
    action: 'ALLOW',
    destination: 'internet',
    targetPeerId: null,
    cidr: null,
    family: 'both',
    protocol: 'any',
    ports: null,
    log: false,
    ...data,
  };
}
function policy(rules: FirewallRule[] = []) {
  return { ...defaultFirewallPolicy(), enabled: true, rules };
}

describe('independent firewall compiler', () => {
  test.each([false, true])(
    'default deny and verified sources, IPv6=%s',
    (ipv6) => {
      const plan = compilePolicy('wg0', peers, policy(), ipv6);
      const text = plan.rules.join('\n');
      expect(text).not.toContain(ipv6 ? 'fd00::4' : '10.8.0.4');
      expect(text).toContain(ipv6 ? '-s 2001:db8::/64' : '-s 192.0.2.0/24');
      for (const chain of plan.chains.filter(
        (chain) => !chain.endsWith('_d')
      )) {
        expect(plan.rules).toContain(`-A ${chain} -j DROP`);
      }
      expect(text).toContain(
        '--ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT'
      );
      expect(text).not.toContain('--ctstate ESTABLISHED,RELATED -j ACCEPT');
      expect(text).not.toContain('-p tcp');
    }
  );

  test('global internet permission cannot implicitly permit peers, LAN, Docker or server', () => {
    const plan = compilePolicy(
      'wg0',
      peers,
      { ...policy([rule()]), dockerCidrs: ['172.18.0.0/16'] },
      false
    );
    const accepts = plan.rules.filter(
      (entry) => entry.endsWith('-j ACCEPT') && !entry.includes('--ctdir')
    );
    expect(accepts).toEqual(['-A WGP_wg0_i -j ACCEPT']);
    expect(
      plan.rules.indexOf('-A WGP_wg0_d -d 172.18.0.0/16 -j WGP_wg0_c')
    ).toBeLessThan(
      plan.rules.indexOf('-A WGP_wg0_d -d 172.16.0.0/12 -j WGP_wg0_l')
    );
    expect(plan.rules).toContain(
      '-A WGP_wg0_d -m addrtype --dst-type LOCAL,BROADCAST,MULTICAST -j WGP_wg0_s'
    );
    const broad = compilePolicy(
      'wg0',
      peers,
      policy([rule({ destination: 'any' })]),
      false
    );
    expect(broad.rules).not.toContain('-A WGP_wg0_p -j ACCEPT');
  });

  test('peer exceptions precede group and global rules; priority and DENY determine ties', () => {
    const rules = [
      rule({ id: 'global', priority: 0 }),
      rule({
        id: 'group',
        scope: 'group',
        groupId: 'team',
        priority: 0,
        action: 'DENY',
      }),
      rule({ id: 'peer-deny', scope: 'peer', peerId: 1, action: 'DENY' }),
      rule({ id: 'peer-allow', scope: 'peer', peerId: 1 }),
      rule({
        id: 'exception',
        scope: 'peer',
        peerId: 1,
        priority: 1,
        protocol: 'tcp',
        ports: '443',
      }),
    ];
    const plan = compilePolicy(
      'wg0',
      peers,
      {
        ...policy(rules),
        groups: [{ id: 'team', name: 'Team', peerIds: [1, 3] }],
      },
      false
    );
    const internet = plan.rules.filter(
      (entry) => entry.startsWith('-A WGP_wg0_i') && !entry.includes('-j LOG')
    );
    expect(internet).toEqual([
      '-A WGP_wg0_i -s 10.8.0.2/32 -p tcp --dport 443 -j ACCEPT',
      '-A WGP_wg0_i -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT',
      '-A WGP_wg0_i -s 10.8.0.2/32 -j DROP',
      '-A WGP_wg0_i -s 192.0.2.0/24 -j DROP',
      '-A WGP_wg0_i -s 10.8.0.2/32 -j ACCEPT',
      '-A WGP_wg0_i -s 192.0.2.0/24 -j ACCEPT',
      '-A WGP_wg0_i -s 10.8.0.2/32 -j DROP',
      '-A WGP_wg0_i -s 192.0.2.0/24 -j DROP',
      '-A WGP_wg0_i -j ACCEPT',
      '-A WGP_wg0_i -j DROP',
    ]);
  });

  test.each([false, true])(
    'individual peer permission is directional and protocol-specific, IPv6=%s',
    (ipv6) => {
      const plan = compilePolicy(
        'wg0',
        peers,
        policy([
          rule({
            scope: 'peer',
            peerId: 1,
            destination: 'peers',
            targetPeerId: 2,
            protocol: 'tcp',
            ports: '8000-8080',
          }),
        ]),
        ipv6
      );
      const entries = plan.rules.filter(
        (entry) =>
          entry.startsWith('-A WGP_wg0_p') && entry.endsWith('-j ACCEPT')
      );
      expect(entries.length).toBe(2);
      expect(
        entries.every((entry) =>
          entry.includes(
            `-d ${ipv6 ? 'fd00::3/128' : '10.8.0.3/32'} -p tcp --dport 8000:8080`
          )
        )
      ).toBe(true);
      expect(
        entries.some((entry) =>
          entry.includes(`-s ${ipv6 ? 'fd00::3' : '10.8.0.3'}`)
        )
      ).toBe(false);
    }
  );

  test('IPv6 ICMP and CIDR families are separate; disabled rules are omitted', () => {
    const data = policy([
      rule({ destination: 'cidr', cidr: '2001:db8::1', protocol: 'icmp' }),
      rule({ id: 'disabled', enabled: false }),
    ]);
    expect(
      compilePolicy('wg0', peers, data, false).rules.some((entry) =>
        entry.includes('-p ')
      )
    ).toBe(false);
    expect(
      compilePolicy('wg0', peers, data, true).rules.some((entry) =>
        entry.includes('-d 2001:db8::1/128 -p ipv6-icmp')
      )
    ).toBe(true);
  });

  test('routes and legacy allowedIps never become permissions', () => {
    const extra = peers.map((peer) => ({
      ...peer,
      allowedIps: ['0.0.0.0/0'],
      firewallIps: ['::/0'],
    }));
    expect(compilePolicy('wg0', extra, policy(), false)).toEqual(
      compilePolicy('wg0', peers, policy(), false)
    );
  });
});

describe('validation and persistence', () => {
  test.each([
    { ports: '0', protocol: 'tcp' },
    { ports: '65536', protocol: 'tcp' },
    { ports: '90-80', protocol: 'udp' },
    { ports: '443', protocol: 'icmp' },
    { ports: '80;id', protocol: 'tcp' },
    { cidr: '1.1.1.1;id', destination: 'cidr' },
    { peerId: 1 },
    { scope: 'peer' },
    { scope: 'group', groupId: null },
    { targetPeerId: 2 },
    { destination: 'cidr', cidr: '::/0', family: 'ipv4' },
  ])('rejects malformed rules: %j', (overrides) => {
    expect(
      FirewallRuleSchema.safeParse(rule(overrides as Partial<FirewallRule>))
        .success
    ).toBe(false);
  });
  test('rejects duplicate identities and dangling groups', () => {
    expect(
      FirewallPolicySchema.safeParse(policy([rule(), rule()])).success
    ).toBe(false);
    expect(
      FirewallPolicySchema.safeParse(
        policy([rule({ scope: 'group', groupId: 'unknown' })])
      ).success
    ).toBe(false);
  });
  test('migration preserves legacy mode; stale revisions cannot overwrite', async () => {
    const { store } = await databaseFixture();
    expect(await store.firewall.get()).toEqual({
      revision: 0,
      policy: defaultFirewallPolicy(),
    });
    expect(
      await store.transaction((tx) => tx.firewall.update(0, policy([rule()])))
    ).toBe(true);
    expect((await store.firewall.get()).revision).toBe(1);
    expect(
      await store.transaction((tx) => tx.firewall.update(0, policy()))
    ).toBe(false);
    expect((await store.firewall.get()).policy.rules).toHaveLength(1);
  });
  test('non-admin cannot read policy, peers or logs', async () => {
    await expect(get({ id: 1, role: 2 })).rejects.toMatchObject({
      status: 403,
    });
  });
});

describe('application and observability', () => {
  test('advanced mode ignores legacy permits and preserves guards on failure', async () => {
    const { store } = await databaseFixture();
    const network = {
      ...(await store.interfaces.get()),
      firewallEnabled: true,
    };
    const defaults = await store.userConfigs.get();
    const execMock = vi.mocked(exec);
    execMock.mockClear();
    const data = policy([rule()]);
    const clients = peers.map((peer) => ({
      ...peer,
      name: 'Test',
      allowedIps: ['0.0.0.0/0'],
      firewallIps: null,
    }));
    await firewall.rebuildRules(network, clients, defaults, false, {
      revision: 3,
      policy: data,
    });
    expect(firewallRuntime.appliedRevision).toBe(3);
    expect(
      execMock.mock.calls.some(([entry]) => entry.includes('-d 0.0.0.0/0'))
    ).toBe(false);
    execMock.mockClear().mockImplementation(async (command) => {
      if (command.includes('-A WGP_wg0_i')) {
        throw new Error('Host unavailable');
      }
      return '';
    });
    await expect(
      firewall.rebuildRules(network, clients, defaults, false, {
        revision: 4,
        policy: data,
      })
    ).rejects.toThrow('Host unavailable');
    expect(
      execMock.mock.calls.some(([entry]) =>
        /-D (INPUT|FORWARD).*rebuild/.test(entry)
      )
    ).toBe(false);
    expect(firewallRuntime.appliedRevision).toBe(3);
    expect(firewallRuntime.applyError).toBe(true);
    execMock.mockResolvedValue('');
  });
  test('log parser isolates interfaces and validates addresses', () => {
    const line =
      'kernel: WGE:wg0:D:12 IN=wg0 OUT=eth0 SRC=10.8.0.2 DST=1.1.1.1 PROTO=TCP SPT=1000 DPT=443';
    expect(parseFirewallLog(line, 'wg0')).toMatchObject({
      kind: 'DENY',
      rule: '12',
      source: '10.8.0.2',
      destination: '1.1.1.1',
      protocol: 'TCP',
      port: '443',
    });
    expect(parseFirewallLog(line, 'wg1')).toBeUndefined();
    expect(
      parseFirewallLog(line.replace('10.8.0.2', 'invalid'), 'wg0')
    ).toBeUndefined();
    expect(
      policyLogPrefix('123456789012345', 'ALLOW', '499').length
    ).toBeLessThanOrEqual(29);
  });
  test('event retention is bounded', () => {
    for (let i = 0; i < 1100; i++) {
      recordEvent({ kind: 'ALLOW', message: 'sample' });
    }
    expect(securityEvents()).toHaveLength(1000);
    expect(securityEvents()[0]!.id).toBeGreaterThan(securityEvents()[999]!.id);
  });
  test('webhook failures are caught without recursion', async () => {
    const deliver = vi.fn().mockRejectedValue(new Error('offline'));
    const delivery = createAlertDelivery(deliver);
    delivery.enqueue({
      id: 1,
      at: new Date().toISOString(),
      kind: 'failure',
      message: 'Test',
    });
    await delivery.close();
    expect(deliver).toHaveBeenCalledTimes(1);
    expect(firewallRuntime.webhook).toBe('delivery-failed');
  });
});
