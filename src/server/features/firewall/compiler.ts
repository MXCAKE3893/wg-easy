import {
  FirewallPolicySchema,
  type FirewallPolicy,
  type FirewallRule,
} from '#shared/contracts/firewall';
import { normalizePrefix } from '#server/utils/ip';
import { parseInterfaceName } from '#server/utils/interfaceName';

export type PolicyPeer = {
  id: number;
  enabled: boolean;
  ipv4Address: string | null;
  ipv6Address: string | null;
  serverAllowedIps: string[];
};
const zones = [
  'dispatch',
  'peers',
  'server',
  'lan',
  'docker',
  'internet',
] as const;
type Zone = Exclude<(typeof zones)[number], 'dispatch'>;
const suffixes = {
  dispatch: 'd',
  peers: 'p',
  server: 's',
  lan: 'l',
  docker: 'c',
  internet: 'i',
};

export function policyChains(name: string) {
  return zones.map((zone) => `WGP_${name}_${suffixes[zone]}`);
}

export function policyLogPrefix(
  name: string,
  action: 'ALLOW' | 'DENY',
  id: string
) {
  // Linux LOG prefixes are limited to 29 bytes. Rule ordinals map to the saved policy.
  return `WGE:${name}:${action === 'ALLOW' ? 'A' : 'D'}:${id} `;
}

function sources(peer: PolicyPeer, ipv6: boolean) {
  const address = ipv6 ? peer.ipv6Address : peer.ipv4Address;
  if (!address || !peer.enabled) {
    return [];
  }
  return [
    ...new Set(
      [
        address,
        ...peer.serverAllowedIps.filter((ip) => ip.includes(':') === ipv6),
      ].map(normalizePrefix)
    ),
  ];
}

/** Pure compiler: never uses client AllowedIPs to infer permissions. */
export function compilePolicy(
  name: string,
  peers: PolicyPeer[],
  input: FirewallPolicy,
  ipv6: boolean
) {
  parseInterfaceName(name);
  const policy = FirewallPolicySchema.parse(input);
  const chains = policyChains(name);
  const chain = (zone: (typeof zones)[number]) => chains[zones.indexOf(zone)]!;
  const rules: string[] = [];
  const append = (
    target: string,
    match: string,
    action: 'ALLOW' | 'DENY',
    id: string,
    log: boolean
  ) => {
    if (log) {
      rules.push(
        `-A ${target}${match} -m limit --limit 10/min --limit-burst 20 -j LOG --log-prefix "${policyLogPrefix(name, action, id)}"`
      );
    }
    rules.push(
      `-A ${target}${match} -j ${action === 'ALLOW' ? 'ACCEPT' : 'DROP'}`
    );
    if (rules.length > 50000) {
      throw new Error(
        'Policy expands beyond 50000 rules; reduce peers, groups or rules'
      );
    }
  };

  // All policy chains terminate; no unmatched traffic returns to foreign ACCEPTs.
  const root = `WG_CLIENTS_${name}`;
  rules.push(`-A ${root} -m conntrack --ctstate INVALID -j DROP`);
  for (const source of new Set(peers.flatMap((peer) => sources(peer, ipv6)))) {
    rules.push(`-A ${root} -s ${source} -j ${chain('dispatch')}`);
  }
  append(root, '', 'DENY', 'src', policy.logDefaultDeny);
  const dispatch = chain('dispatch');
  // Only the REPLY direction bypasses policy evaluation. Original-direction
  // established packets still meet updated DENY rules after a policy change.
  rules.push(
    `-A ${dispatch} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT`
  );
  // IPv6 has no broadcast address type; ip6tables rejects BROADCAST.
  // Match IPv6 multicast explicitly rather than using IPv4 addrtype flags.
  rules.push(
    `-A ${dispatch} -m addrtype --dst-type ${ipv6 ? 'LOCAL' : 'LOCAL,BROADCAST,MULTICAST'} -j ${chain('server')}`
  );
  if (ipv6) {
    rules.push(`-A ${dispatch} -d ff00::/8 -j ${chain('server')}`);
  }
  rules.push(`-A ${dispatch} -o ${name} -j ${chain('peers')}`);
  for (const [prefixes, zone] of [
    [policy.dockerCidrs, 'docker'],
    [policy.lanCidrs, 'lan'],
  ] as const) {
    for (const prefix of prefixes.filter((ip) => ip.includes(':') === ipv6)) {
      rules.push(
        `-A ${dispatch} -d ${normalizePrefix(prefix)} -j ${chain(zone)}`
      );
    }
  }
  rules.push(`-A ${dispatch} -j ${chain('internet')}`);

  const rank = { peer: 0, group: 1, global: 2 };
  const sorted = policy.rules
    .map((rule, index) => ({ rule, index }))
    .filter(({ rule }) => rule.enabled)
    .sort(
      (a, b) =>
        rank[a.rule.scope] - rank[b.rule.scope] ||
        a.rule.priority - b.rule.priority ||
        Number(a.rule.action === 'ALLOW') - Number(b.rule.action === 'ALLOW') ||
        a.rule.id.localeCompare(b.rule.id)
    );
  for (const zone of zones.filter(
    (zone): zone is Zone => zone !== 'dispatch'
  )) {
    for (const { rule, index } of sorted) {
      if (rule.family !== 'both' && rule.family !== (ipv6 ? 'ipv6' : 'ipv4')) {
        continue;
      }
      // "any" deliberately excludes peer forwarding. It must be explicitly granted.
      if (
        rule.destination === 'any'
          ? zone === 'peers'
          : rule.destination !== 'cidr' && rule.destination !== zone
      ) {
        continue;
      }
      const sourceMatches =
        rule.scope === 'global'
          ? ['']
          : peers
              .filter((peer) =>
                rule.scope === 'peer'
                  ? peer.id === rule.peerId
                  : policy.groups
                      .find((group) => group.id === rule.groupId)
                      ?.peerIds.includes(peer.id)
              )
              .flatMap((peer) =>
                sources(peer, ipv6).map((source) => ` -s ${source}`)
              );
      const destinations = destinationMatches(rule, peers, ipv6);
      const protocol =
        rule.protocol === 'any'
          ? ''
          : ` -p ${rule.protocol === 'icmp' && ipv6 ? 'ipv6-icmp' : rule.protocol}`;
      const port = rule.ports ? ` --dport ${rule.ports.replace('-', ':')}` : '';
      for (const source of sourceMatches) {
        for (const destination of destinations) {
          append(
            chain(zone),
            source + destination + protocol + port,
            rule.action,
            String(index),
            rule.log
          );
        }
      }
    }
    append(chain(zone), '', 'DENY', 'end', policy.logDefaultDeny);
  }
  if (rules.length > 50000) {
    throw new Error(
      'Policy expands beyond 50000 rules; reduce peers, groups or rules'
    );
  }
  return { chains, rules };
}

function destinationMatches(
  rule: FirewallRule,
  peers: PolicyPeer[],
  ipv6: boolean
) {
  if (rule.cidr) {
    return rule.cidr.includes(':') === ipv6
      ? [` -d ${normalizePrefix(rule.cidr)}`]
      : [];
  }
  if (rule.targetPeerId !== null) {
    const peer = peers.find(
      (peer) => peer.id === rule.targetPeerId && peer.enabled
    );
    const address = ipv6 ? peer?.ipv6Address : peer?.ipv4Address;
    return address ? [` -d ${normalizePrefix(address)}`] : [];
  }
  return [''];
}
