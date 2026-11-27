import type { FirewallPolicy } from '#shared/contracts/firewall';

export type SecurityEvent = {
  id: number;
  at: string;
  kind: 'ALLOW' | 'DENY' | 'connection' | 'failure' | 'recovery';
  message: string;
  peerId?: number;
  source?: string;
  destination?: string;
  protocol?: string;
  port?: string;
  rule?: string;
};
let sequence = 0;
const events: SecurityEvent[] = [];
const listeners = new Set<(event: SecurityEvent) => void>();
export const firewallRuntime = {
  appliedRevision: null as number | null,
  appliedAt: null as string | null,
  applyError: false,
  logging: 'not-started',
  webhook: 'not-configured',
  monitoring: 'not-started',
  policy: undefined as FirewallPolicy | undefined,
};

export function recordEvent(event: Omit<SecurityEvent, 'id' | 'at'>) {
  const entry = { ...event, id: ++sequence, at: new Date().toISOString() };
  events.push(entry);
  if (events.length > 1000) {
    events.shift();
  }
  for (const listener of listeners) {
    listener(entry);
  }
  return entry;
}
export function securityEvents() {
  return events.slice().reverse();
}
export function onSecurityEvent(listener: (event: SecurityEvent) => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
export function policyApplied(revision: number, policy: FirewallPolicy) {
  const recovered = firewallRuntime.applyError;
  Object.assign(firewallRuntime, {
    appliedRevision: revision,
    appliedAt: new Date().toISOString(),
    applyError: false,
    policy,
  });
  if (recovered) {
    recordEvent({
      kind: 'recovery',
      message: 'Firewall policy applied successfully',
    });
  }
}
export function policyFailed() {
  if (!firewallRuntime.applyError) {
    recordEvent({
      kind: 'failure',
      message:
        'Firewall update failed; VPN traffic remains guarded. Maintenance will retry.',
    });
  }
  firewallRuntime.applyError = true;
}
