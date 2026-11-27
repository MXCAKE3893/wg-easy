import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';

import { isIP } from 'is-ip';

import {
  firewallRuntime,
  onSecurityEvent,
  recordEvent,
  type SecurityEvent,
} from './runtime';

import { getDatabase } from '#db';
import { wg } from '#server/utils/wgHelper';
import { mergeClientStatuses } from '#server/utils/clientStatus';
import { isPeerConnected } from '#shared/utils/time';
import { startMaintenance } from '#server/jobs/maintenance';

type PeerStatus = {
  id: number;
  name: string;
  enabled: boolean;
  connected: boolean;
  ipv4Address: string;
  ipv6Address: string;
  endpoint: string | null;
  latestHandshakeAt: string | null;
  transferRx: number;
  transferTx: number;
};
let peers: PeerStatus[] = [];
export function peerSnapshot() {
  return peers;
}

export function parseFirewallLog(line: string, name: string) {
  const start = line.indexOf(`WGE:${name}:`);
  if (start < 0) {
    return;
  }
  const text = line.slice(start + name.length + 5);
  const header = /^([AD]):([a-z0-9]+) /.exec(text);
  if (!header) {
    return;
  }
  const fields = Object.fromEntries(
    [...text.matchAll(/\b([A-Z]+)=([^ ]*)/g)].map((match) => [
      match[1],
      match[2],
    ])
  );
  if (!fields.SRC || !fields.DST || !isIP(fields.SRC) || !isIP(fields.DST)) {
    return;
  }
  return {
    kind: header[1] === 'A' ? ('ALLOW' as const) : ('DENY' as const),
    message: 'Firewall packet (rate-limited sample)',
    source: fields.SRC,
    destination: fields.DST,
    protocol: fields.PROTO?.slice(0, 20),
    port: fields.DPT?.slice(0, 5),
    rule: header[2],
  };
}

/** Single bounded queue. Webhook errors never recurse into notification events. */
export function createAlertDelivery(
  deliver: (event: SecurityEvent) => Promise<void>
) {
  const queue: SecurityEvent[] = [];
  let pending: Promise<void> | undefined;
  let closed = false;
  function enqueue(event: SecurityEvent) {
    if (closed || queue.length >= 50) {
      return;
    }
    queue.push(event);
    pending ??= (async () => {
      while (queue.length) {
        const next = queue.shift()!;
        try {
          await deliver(next);
          firewallRuntime.webhook = 'ready';
        } catch {
          firewallRuntime.webhook = 'delivery-failed';
        }
      }
    })().finally(() => {
      pending = undefined;
    });
  }
  return {
    enqueue,
    async close() {
      closed = true;
      queue.length = 0;
      await pending;
    },
  };
}

export function startSecurityMonitor() {
  let stopped = false;
  let logProcess: ChildProcess | undefined;
  let retryLogAt = 0;
  let logName = '';
  let logUnavailable = false;
  let initialized = false;
  const denied = new Map<
    string,
    { count: number; since: number; notified: boolean }
  >();
  const cooldowns = new Map<string, number>();
  let configuredWebhook: string | null | undefined;
  let url: URL | undefined;
  function configureWebhook(value: string | null) {
    const selected = value ?? process.env.WG_ALERT_WEBHOOK_URL ?? null;
    if (selected === configuredWebhook) {
      return;
    }
    configuredWebhook = selected;
    url = undefined;
    if (!selected) {
      firewallRuntime.webhook = 'not-configured';
      return;
    }
    try {
      const parsed = new URL(selected);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
        throw new Error('HTTPS required');
      }
      url = parsed;
      firewallRuntime.webhook = 'ready';
    } catch {
      firewallRuntime.webhook = 'invalid-configuration';
    }
  }
  configureWebhook(null);
  const delivery = createAlertDelivery(async (event) => {
    if (!url) {
      return;
    }
    const response = await fetch(url, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'wg-easy', event }),
    });
    await response.body?.cancel();
    if (!response.ok) {
      throw new Error('Webhook rejected notification');
    }
  });
  const unsubscribe = onSecurityEvent((event) => {
    const config = firewallRuntime.policy?.alerts;
    configureWebhook(config?.webhookUrl ?? null);
    if (!config || !url || !firewallRuntime.policy?.enabled) {
      return;
    }
    let alert =
      (event.kind === 'connection' && config.connections) ||
      ((event.kind === 'failure' || event.kind === 'recovery') &&
        config.failures);
    if (event.kind === 'DENY' && config.deniedTraffic) {
      const key = event.source ?? 'unknown';
      if (denied.size >= 1000 && !denied.has(key)) {
        denied.delete(denied.keys().next().value!);
      }
      let bucket = denied.get(key);
      if (!bucket || Date.now() - bucket.since >= 60000) {
        bucket = { count: 0, since: Date.now(), notified: false };
        denied.set(key, bucket);
      }
      bucket.count++;
      if (!bucket.notified && bucket.count >= config.denyThreshold) {
        bucket.notified = true;
        alert = true;
      }
    }
    if (!alert) {
      return;
    }
    const key = `${event.kind}:${event.peerId ?? event.source ?? ''}`;
    const now = Date.now();
    if (now - (cooldowns.get(key) ?? 0) < 60000) {
      return;
    }
    if (cooldowns.size >= 2000) {
      cooldowns.clear();
    }
    cooldowns.set(key, now);
    delivery.enqueue(event);
  });

  function stopLogs() {
    const child = logProcess;
    logProcess = undefined;
    child?.kill();
  }

  function startLogs(name: string, enabled: boolean) {
    if (!enabled || (logProcess && name !== logName)) {
      stopLogs();
      firewallRuntime.logging = 'disabled';
    }
    if (!enabled || logProcess || Date.now() < retryLogAt || stopped) {
      return;
    }
    if (process.platform !== 'linux') {
      firewallRuntime.logging = 'unavailable-platform';
      return;
    }
    logName = name;
    firewallRuntime.logging = 'starting';
    // Never read historical kernel messages or expose unrelated host logs.
    const child = spawn(
      'dmesg',
      ['--follow-new', '--notime', '--color=never'],
      { stdio: ['ignore', 'pipe', 'ignore'] }
    );
    logProcess = child;
    const reader = createInterface({ input: child.stdout! });
    child.once('spawn', () => {
      firewallRuntime.logging = 'streaming';
    });
    reader.on('line', (line) => {
      if (logUnavailable) {
        logUnavailable = false;
        recordEvent({
          kind: 'recovery',
          message: 'Kernel log collection recovered',
        });
      }
      const event = parseFirewallLog(line, name);
      if (event) {
        const peer = peers.find(
          (peer) =>
            peer.ipv4Address === event.source ||
            peer.ipv6Address === event.source
        );
        recordEvent({ ...event, peerId: peer?.id });
      }
    });
    const unavailable = () => {
      reader.close();
      if (logProcess !== child) {
        return;
      }
      logProcess = undefined;
      retryLogAt = Date.now() + 60000;
      firewallRuntime.logging = 'unavailable-permission-or-command';
      if (!logUnavailable) {
        logUnavailable = true;
        recordEvent({
          kind: 'failure',
          message:
            'Kernel log collection unavailable; check dmesg and kernel log permissions',
        });
      }
    };
    child.once('error', unavailable);
    child.once('exit', unavailable);
  }

  const stopPolling = startMaintenance(async () => {
    try {
      const database = getDatabase();
      const { policy } = await database.firewall.get();
      const network = await database.interfaces.get();
      firewallRuntime.policy = policy;
      configureWebhook(policy.alerts.webhookUrl);
      startLogs(network.name, policy.enabled && network.firewallEnabled);
      const clients = await database.clients.getAllPublic();
      const statuses = mergeClientStatuses(
        clients,
        await wg.dump(network.name)
      );
      const next = statuses.map((peer) => ({
        id: peer.id,
        name: peer.name,
        enabled: peer.enabled,
        connected: peer.enabled && isPeerConnected(peer),
        ipv4Address: peer.ipv4Address,
        ipv6Address: peer.ipv6Address,
        endpoint: peer.endpoint,
        latestHandshakeAt: peer.latestHandshakeAt?.toISOString() ?? null,
        transferRx: peer.transferRx ?? 0,
        transferTx: peer.transferTx ?? 0,
      }));
      if (initialized) {
        for (const peer of next) {
          const previous = peers.find((old) => old.id === peer.id);
          if ((previous?.connected ?? false) !== peer.connected) {
            recordEvent({
              kind: 'connection',
              peerId: peer.id,
              message: peer.connected ? 'Peer connected' : 'Peer disconnected',
            });
          }
        }
      }
      peers = next;
      initialized = true;
      if (firewallRuntime.monitoring === 'failed') {
        recordEvent({ kind: 'recovery', message: 'Peer monitoring recovered' });
      }
      firewallRuntime.monitoring = 'ready';
    } catch {
      if (firewallRuntime.monitoring !== 'failed') {
        recordEvent({ kind: 'failure', message: 'Peer monitoring failed' });
      }
      firewallRuntime.monitoring = 'failed';
    }
  }, 15000);

  return async () => {
    stopped = true;
    await stopPolling();
    stopLogs();
    unsubscribe();
    await delivery.close();
    peers = [];
  };
}
