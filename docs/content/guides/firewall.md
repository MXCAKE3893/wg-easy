---
title: Firewall & monitoring
---

## Setup

Open **Admin Panel → Firewall & monitoring**. Create groups and rules, review the LAN and Docker CIDRs, then enable **independent policy mode** and save.

Existing installations keep their legacy firewall until policy mode is enabled. Policy mode replaces all legacy `firewallIps` and `AllowedIPs` permissions. Unmatched traffic is denied, including communication between peers. Prepare the required permissions before enabling it. Saving an enabled policy also enables the interface firewall master switch.

Client AllowedIPs and server routes remain routing settings only. A policy change does not require distributing another client configuration; clients still need a route through the VPN for the destination.

## Rules and exceptions

Rules specify scope, action (ALLOW/DENY), destination, IPv4/IPv6, protocol and an optional destination port or inclusive port range. TCP and UDP support ports; ICMP becomes ICMPv6 for IPv6.

First match wins:

1. Peer-specific rules.
2. Rules for any group containing the source peer.
3. Global rules.

Within a scope, lower priority numbers run first. At equal priority DENY runs before ALLOW, followed by rule ID. Give an exception a lower priority number than a conflicting rule in the same scope.

For example, a global Internet ALLOW can be overridden by a group Internet DENY. Add a peer-specific TCP/443 ALLOW to permit that peer's exception.

## Destinations

Traffic is classified in this order:

1. Server-local addresses (also broadcast and multicast).
2. Traffic forwarded to the VPN interface: peers and networks routed behind peers.
3. Explicit Docker CIDRs.
4. LAN CIDRs (private address ranges are prefilled).
5. Internet: remaining destinations.

Review these lists for your topology; Docker and physical LAN networks cannot always be detected from inside a container. A Docker destination using the server's own local address is classified as server-local.

**Any non-peer destination** deliberately excludes peer forwarding. To allow A to initiate TCP/443 to B, use Peer scope A, destination Peers, target B, TCP, port 443, ALLOW. Reverse initiation remains denied. A CIDR rule can explicitly allow a routed network behind another peer.

Enabled peers' assigned addresses and server-side advertised networks identify their sources. Disabled and unknown sources receive no permits. Conntrack automatically allows ESTABLISHED/RELATED replies from verified VPN sources; original-direction packets continue to be evaluated against the current policy. Existing reply-state entries expire normally rather than being globally flushed. This feature filters VPN ingress, not arbitrary host, Docker or Internet ingress.

## Applying policies

Saves apply on the running server. Updates are serialized; stale revisions are rejected rather than overwriting another administrator's changes.

Rebuild guards block VPN traffic while both address families are updated. A failed rebuild keeps guards installed and maintenance retries. Desired settings can already be saved when applying to the host fails: compare saved and applied revisions and reload before retrying. The interface master switch can explicitly disable all filtering. Disabling policy mode alone returns to legacy filtering.

## Monitoring and alerts

Peer state refreshes every 15 seconds. “Connected” means a handshake within the last ten minutes, not a guarantee of current reachability. The endpoint includes the source IP and port. RX/TX are server-side byte counters for the current peer/interface configuration and can reset on reconfiguration.

Configure the HTTPS webhook URL and connection, denied-traffic and failure alerts on this page. An empty URL falls back to the server environment variable `WG_ALERT_WEBHOOK_URL`. Only administrators can read or change policy and notification settings. Webhooks receive JSON:

```json
{"service":"wg-easy","event":{"id":1,"at":"2026-01-01T00:00:00.000Z","kind":"connection","peerId":1,"message":"Peer connected"}}
```

Denied-traffic alerts count sampled denial logs per source within one minute. They require working kernel log collection, not just firewall enforcement. Notifications are deduplicated for one minute per event kind/source or peer. Delivery has a five-second timeout, a bounded queue and no automatic retry; check webhook status for delivery failures.

## Traffic logs

Enable logging on individual rules and/or default denials. The UI retains the latest 1,000 events in process memory, shows the latest 200 matching events and supports text filtering. Events reset at restart. Logging is sampled at 10 messages/minute with a burst of 20 per compiled rule; this is not a lossless audit log or a packet-rate IDS.

The container includes util-linux `dmesg`. Collection requires Linux kernel log access, which standard container permissions may deny. The UI reports unavailable collection separately from firewall enforcement and retries periodically. Only messages with this VPN interface's wg-easy prefix are exposed. Rule numbers are zero-based positions at emission time; `src` and `end` identify default denials.

Depending on the host, kernel log access requires an explicitly granted `SYSLOG` capability and a readable kernel log device; logging from non-initial network namespaces may also require the host setting `net.netfilter.nf_log_all_netns=1`. These are host security decisions, not settings wg-easy changes automatically. Do not enable privileged mode just to obtain logs. Kernel rate limits can discard additional messages.
