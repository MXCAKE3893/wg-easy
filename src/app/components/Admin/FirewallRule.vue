<template>
  <FormGroup>
    <FormHeading>{{ rule.name || rule.id }}</FormHeading>
    <FormTextField
      :id="`name-${rule.id}`"
      v-model="rule.name"
      :label="$t('firewallAdmin.name')"
    />
    <FormSwitchField
      :id="`enabled-${rule.id}`"
      v-model="rule.enabled"
      :label="$t('firewallAdmin.enabled')"
    />
    <label :for="`scope-${rule.id}`">{{ $t('firewallAdmin.scope') }}</label>
    <select
      :id="`scope-${rule.id}`"
      v-model="rule.scope"
      class="ui-input"
      @change="resetScope"
    >
      <option
        v-for="scope in ['global', 'group', 'peer']"
        :key="scope"
        :value="scope"
      >
        {{ $t(`firewallAdmin.scopes.${scope}`) }}
      </option>
    </select>
    <template v-if="rule.scope === 'peer'">
      <label :for="`peer-${rule.id}`">{{ $t('firewallAdmin.peer') }}</label>
      <select
        :id="`peer-${rule.id}`"
        v-model="rule.peerId"
        required
        class="ui-input"
      >
        <option :value="null" disabled>—</option>
        <option v-for="peer in peers" :key="peer.id" :value="peer.id">
          {{ peer.name }} (#{{ peer.id }})
        </option>
      </select>
    </template>
    <template v-if="rule.scope === 'group'">
      <label :for="`group-${rule.id}`">{{ $t('firewallAdmin.group') }}</label>
      <select
        :id="`group-${rule.id}`"
        v-model="rule.groupId"
        required
        class="ui-input"
      >
        <option :value="null" disabled>—</option>
        <option v-for="group in groups" :key="group.id" :value="group.id">
          {{ group.name }}
        </option>
      </select>
    </template>
    <FormNumberField
      :id="`priority-${rule.id}`"
      v-model="rule.priority"
      :label="$t('firewallAdmin.priority')"
    />
    <label :for="`action-${rule.id}`">{{ $t('firewallAdmin.action') }}</label>
    <select :id="`action-${rule.id}`" v-model="rule.action" class="ui-input">
      <option>ALLOW</option>
      <option>DENY</option>
    </select>
    <label :for="`destination-${rule.id}`">
      {{ $t('firewallAdmin.destination') }}
    </label>
    <select
      :id="`destination-${rule.id}`"
      v-model="rule.destination"
      class="ui-input"
      @change="resetDestination"
    >
      <option
        v-for="destination in destinations"
        :key="destination"
        :value="destination"
      >
        {{ $t(`firewallAdmin.destinations.${destination}`) }}
      </option>
    </select>
    <FormNullTextField
      v-if="rule.destination === 'cidr'"
      :id="`cidr-${rule.id}`"
      v-model="rule.cidr"
      :label="$t('firewallAdmin.cidr')"
    />
    <template v-if="rule.destination === 'peers'">
      <label :for="`target-${rule.id}`">
        {{ $t('firewallAdmin.targetPeer') }}
      </label>
      <select
        :id="`target-${rule.id}`"
        v-model="rule.targetPeerId"
        class="ui-input"
      >
        <option :value="null">{{ $t('firewallAdmin.allPeers') }}</option>
        <option v-for="peer in peers" :key="peer.id" :value="peer.id">
          {{ peer.name }} (#{{ peer.id }})
        </option>
      </select>
    </template>
    <label :for="`family-${rule.id}`">{{ $t('firewallAdmin.family') }}</label>
    <select :id="`family-${rule.id}`" v-model="rule.family" class="ui-input">
      <option value="both">IPv4 + IPv6</option>
      <option value="ipv4">IPv4</option>
      <option value="ipv6">IPv6</option>
    </select>
    <label :for="`protocol-${rule.id}`">
      {{ $t('firewallAdmin.protocol') }}
    </label>
    <select
      :id="`protocol-${rule.id}`"
      v-model="rule.protocol"
      class="ui-input"
      @change="resetProtocol"
    >
      <option value="any">{{ $t('firewallAdmin.allProtocols') }}</option>
      <option value="tcp">TCP</option>
      <option value="udp">UDP</option>
      <option value="icmp">ICMP / ICMPv6</option>
    </select>
    <FormNullTextField
      v-if="rule.protocol === 'tcp' || rule.protocol === 'udp'"
      :id="`ports-${rule.id}`"
      v-model="rule.ports"
      :label="$t('firewallAdmin.ports')"
    />
    <FormSwitchField
      :id="`log-${rule.id}`"
      v-model="rule.log"
      :label="$t('firewallAdmin.logRule')"
    />
    <div class="col-span-full">
      <BaseSecondaryButton type="button" @click="$emit('remove')">
        {{ $t('common.actions.delete') }}
      </BaseSecondaryButton>
    </div>
  </FormGroup>
</template>

<script setup lang="ts">
import type { FirewallPolicy, FirewallRule } from '#shared/contracts/firewall';

const rule = defineModel<FirewallRule>({ required: true });
defineProps<{
  groups: FirewallPolicy['groups'];
  peers: { id: number; name: string }[];
}>();
defineEmits<{ remove: [] }>();
const destinations = [
  'any',
  'peers',
  'server',
  'lan',
  'docker',
  'internet',
  'cidr',
];
function resetScope() {
  rule.value.peerId = null;
  rule.value.groupId = null;
}
function resetDestination() {
  rule.value.cidr = rule.value.destination === 'cidr' ? '' : null;
  rule.value.targetPeerId = null;
}
function resetProtocol() {
  rule.value.ports = null;
}
</script>
