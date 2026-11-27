import { createError } from 'nuxt/server';

import { compilePolicy } from './compiler';
import { firewallRuntime, securityEvents } from './runtime';
import { peerSnapshot } from './monitor';

import { getDatabase } from '#db';
import { authorize } from '#server/features/authorization';
import { commit } from '#server/features/vpn/lifecycle';
import { WG_ENV } from '#server/utils/config';
import type { Actor } from '#shared/contracts/identity';
import type { FirewallPolicy } from '#shared/contracts/firewall';

export async function get(actor: Actor) {
  authorize(actor, 'admin', 'any');
  const { policy, revision } = await getDatabase().firewall.get();
  const network = await getDatabase().interfaces.get();
  const statuses = new Map(peerSnapshot().map((peer) => [peer.id, peer]));
  const peers = (await getDatabase().clients.getAllPublic()).map((peer) => {
    const status = statuses.get(peer.id);
    return {
      id: peer.id,
      name: peer.name,
      enabled: peer.enabled,
      ipv4Address: peer.ipv4Address,
      ipv6Address: peer.ipv6Address,
      connected: peer.enabled && (status?.connected ?? false),
      endpoint: status?.endpoint ?? null,
      latestHandshakeAt: status?.latestHandshakeAt ?? null,
      transferRx: status?.transferRx ?? 0,
      transferTx: status?.transferTx ?? 0,
    };
  });
  return {
    policy,
    revision,
    firewallEnabled: network.firewallEnabled,
    runtime: {
      appliedRevision: firewallRuntime.appliedRevision,
      appliedAt: firewallRuntime.appliedAt,
      applyError: firewallRuntime.applyError,
      logging: firewallRuntime.logging,
      webhook: firewallRuntime.webhook,
      monitoring: firewallRuntime.monitoring,
    },
    peers,
    events: securityEvents(),
  };
}

export async function update(
  actor: Actor,
  revision: number,
  policy: FirewallPolicy
) {
  authorize(actor, 'admin', 'any');
  await commit(async (tx) => {
    const peers = await tx.clients.getAll();
    const ids = new Set(peers.map((peer) => peer.id));
    const references = [
      ...policy.groups.flatMap((group) => group.peerIds),
      ...policy.rules.flatMap((rule) =>
        [rule.peerId, rule.targetPeerId].filter(
          (id): id is number => id !== null
        )
      ),
    ];
    if (references.some((id) => !ids.has(id))) {
      throw createError({ status: 422, message: 'Unknown peer in policy' });
    }
    const network = await tx.interfaces.get();
    compilePolicy(network.name, peers, policy, false);
    if (!WG_ENV.DISABLE_IPV6) {
      compilePolicy(network.name, peers, policy, true);
    }
    if (!(await tx.firewall.update(revision, policy))) {
      throw createError({
        status: 409,
        message: 'Policy changed. Reload before saving.',
      });
    }
    if (policy.enabled) {
      await tx.interfaces.update({ firewallEnabled: true });
    }
  });
}
