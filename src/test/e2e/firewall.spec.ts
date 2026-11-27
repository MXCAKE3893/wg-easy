import {
  defaultFirewallPolicy,
  type FirewallRule,
} from '../../shared/contracts/firewall';

import { credentials, expect, test } from './fixtures';

test.use({ ipv6: true });

test('a routed LAN can reply to an allowed TCP connection from a VPN peer', async ({
  request,
  app,
}) => {
  const headers = { Origin: app.url };
  const login = await request.post('/api/auth/password', {
    headers,
    data: { ...credentials, remember: false },
  });
  expect(login.ok()).toBe(true);
  const network = await (await request.get('/api/admin/interface')).json();
  const site4 = '192.0.2.10';
  const site6 = '2001:db8:1::10';
  const routes = ['192.0.2.0/24', '2001:db8:1::/64'];
  async function connectPeer(
    index: number,
    name: string,
    serverAllowedIps: string[],
    firewallIps: string[]
  ) {
    const created = await request.post('/api/client', {
      headers,
      data: { name, expiresAt: null },
    });
    expect(created.ok()).toBe(true);
    const url = `/api/client/${(await created.json()).clientId}`;
    const peer = await (await request.get(url)).json();
    const saved = await request.post(url, {
      headers,
      data: {
        ...peer,
        allowedIps: [network.ipv4Cidr, network.ipv6Cidr, ...routes],
        serverAllowedIps,
        firewallIps,
      },
    });
    expect(saved.ok()).toBe(true);
    await app.connectClient(
      await (await request.get(url + '/configuration')).text(),
      index
    );
    // Let the server learn each peer's endpoint before it forwards traffic.
    await app.execClient(['ping', '-c', '1', '-W', '3', '10.8.0.1'], index);
    await app.execClient(
      [
        'sh',
        '-c',
        `node -e 'require("node:net").createServer(s => s.end("ok")).listen(443)' >/tmp/tcp-listener.log 2>&1 &`,
      ],
      index
    );
    return peer;
  }
  const peer = await connectPeer(
    1,
    'Admin',
    [],
    [`${site4}:443/tcp`, `[${site6}]:443/tcp`]
  );
  const gateway = await connectPeer(2, 'Gateway', routes, ['10.8.0.1']);
  await app.execClient(['ip', 'addr', 'add', site4 + '/32', 'dev', 'lo'], 2);
  await app.execClient(['ip', 'addr', 'add', site6 + '/128', 'dev', 'lo'], 2);

  const pairs = [
    [peer.ipv4Address, site4],
    [peer.ipv6Address, site6],
  ] as const;
  const connect = (index: number, source: string, dest: string) =>
    app.execClient(['nc', '-w', '2', '-s', source, dest, '443'], index);

  // Establish that both listeners and the routes back to the VPN peer work.
  for (const [admin, site] of pairs) {
    await expect(async () => {
      expect(await connect(2, site, admin)).toBe('ok');
      expect(await connect(1, admin, site)).toBe('ok');
    }).toPass({ timeout: 10_000 });
  }
  const enabled = await request.post('/api/admin/interface', {
    headers,
    data: { ...network, firewallEnabled: true },
  });
  expect(enabled.ok()).toBe(true);
  for (const [admin, site] of pairs) {
    expect(await connect(1, admin, site)).toBe('ok');
    await expect(connect(2, site, admin)).rejects.toMatchObject({ code: 1 });
  }

  const unchangedConfiguration = await (
    await request.get(`/api/client/${peer.id}/configuration`)
  ).text();
  const independent = { ...defaultFirewallPolicy(), enabled: true };
  async function applyPolicy() {
    const { revision } = await (
      await request.get('/api/admin/firewall')
    ).json();
    const response = await request.post('/api/admin/firewall', {
      headers,
      data: { revision, policy: independent },
    });
    expect(await response.text()).toContain('"success":true');
    expect(response.ok()).toBe(true);
  }
  const makeRule = (data: Partial<FirewallRule>): FirewallRule => ({
    id: 'rule',
    name: 'Policy test',
    enabled: true,
    scope: 'global',
    peerId: null,
    groupId: null,
    priority: 100,
    action: 'ALLOW',
    destination: 'peers',
    targetPeerId: null,
    cidr: null,
    family: 'both',
    protocol: 'tcp',
    ports: '443',
    log: true,
    ...data,
  });
  // Merely having routes, legacy permits and established connections grants nothing.
  await applyPolicy();
  for (const [admin, site] of pairs) {
    await expect(connect(1, admin, site)).rejects.toMatchObject({ code: 1 });
  }
  independent.groups = [{ id: 'admins', name: 'Admins', peerIds: [peer.id] }];
  independent.rules = [
    makeRule({
      id: 'global-deny',
      action: 'DENY',
      protocol: 'any',
      ports: null,
    }),
    makeRule({
      id: 'group-site4',
      scope: 'group',
      groupId: 'admins',
      destination: 'cidr',
      cidr: site4,
    }),
    makeRule({
      id: 'group-site6',
      scope: 'group',
      groupId: 'admins',
      destination: 'cidr',
      cidr: site6,
    }),
    makeRule({
      id: 'specific-peer',
      scope: 'peer',
      peerId: peer.id,
      targetPeerId: gateway.id,
    }),
  ];
  await applyPolicy();
  for (const [admin, site] of pairs) {
    // Returning packets from the routed site are automatically accepted.
    expect(await connect(1, admin, site)).toBe('ok');
    await expect(connect(2, site, admin)).rejects.toMatchObject({ code: 1 });
  }
  expect(await connect(1, peer.ipv4Address, gateway.ipv4Address)).toBe('ok');
  expect(await connect(1, peer.ipv6Address, gateway.ipv6Address)).toBe('ok');
  independent.rules.push(
    makeRule({
      id: 'peer-revoke',
      scope: 'peer',
      peerId: peer.id,
      destination: 'peers',
      priority: 0,
      action: 'DENY',
    })
  );
  await applyPolicy();
  for (const [admin, site] of pairs) {
    await expect(connect(1, admin, site)).rejects.toMatchObject({ code: 1 });
  }
  expect(
    await (await request.get(`/api/client/${peer.id}/configuration`)).text()
  ).toBe(unchangedConfiguration);
});
