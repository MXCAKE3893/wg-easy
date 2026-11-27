<template>
  <div v-if="data" class="space-y-6">
    <p class="callout">{{ $t('firewallAdmin.description') }}</p>
    <p class="text-sm">{{ $t('firewallAdmin.precedence') }}</p>
    <p v-if="!data.firewallEnabled" role="status" class="callout">
      {{ $t('firewallAdmin.masterDisabled') }}
    </p>
    <p
      v-if="
        data.runtime.applyError ||
        (data.policy.enabled && data.runtime.appliedRevision !== data.revision)
      "
      role="alert"
      class="callout"
    >
      {{ $t('firewallAdmin.pending') }}
    </p>
    <dl class="surface grid gap-3 p-4 text-sm sm:grid-cols-2">
      <div>
        <dt>{{ $t('firewallAdmin.savedRevision') }}</dt>
        <dd>{{ data.revision }}</dd>
      </div>
      <div>
        <dt>{{ $t('firewallAdmin.appliedRevision') }}</dt>
        <dd>
          {{ data.runtime.appliedRevision ?? '—' }} /
          {{ data.runtime.appliedAt ?? '—' }}
        </dd>
      </div>
      <div>
        <dt>{{ $t('firewallAdmin.kernelLogs') }}</dt>
        <dd>{{ data.runtime.logging }}</dd>
      </div>
      <div>
        <dt>{{ $t('firewallAdmin.webhook') }}</dt>
        <dd>{{ data.runtime.webhook }}</dd>
      </div>
      <div>
        <dt>{{ $t('firewallAdmin.monitoring') }}</dt>
        <dd>{{ data.runtime.monitoring }}</dd>
      </div>
    </dl>
    <FormElement @submit.prevent="save">
      <FormGroup>
        <FormHeading>{{ $t('firewallAdmin.title') }}</FormHeading>
        <FormSwitchField
          id="policy-enabled"
          v-model="draft.enabled"
          :label="$t('firewallAdmin.policyEnabled')"
          :description="$t('firewallAdmin.legacyWarning')"
        />
        <FormSwitchField
          id="default-log"
          v-model="draft.logDefaultDeny"
          :label="$t('firewallAdmin.logDefaultDeny')"
        />
        <div class="col-span-full">
          <p class="mb-2">{{ $t('firewallAdmin.lanCidrs') }}</p>
          <FormArrayField v-model="draft.lanCidrs" name="LAN CIDR" />
        </div>
        <div class="col-span-full">
          <p class="mb-2">{{ $t('firewallAdmin.dockerCidrs') }}</p>
          <FormArrayField v-model="draft.dockerCidrs" name="Docker CIDR" />
        </div>
      </FormGroup>
      <FormGroup>
        <FormHeading>{{ $t('firewallAdmin.alerts') }}</FormHeading>
        <p class="col-span-full text-sm">
          {{ $t('firewallAdmin.webhookHelp') }}
        </p>
        <FormNullTextField
          id="alert-webhook-url"
          v-model="draft.alerts.webhookUrl"
          :label="$t('firewallAdmin.webhookUrl')"
          autocomplete="off"
        />
        <FormSwitchField
          id="alert-connections"
          v-model="draft.alerts.connections"
          :label="$t('firewallAdmin.connectionAlerts')"
        />
        <FormSwitchField
          id="alert-denied"
          v-model="draft.alerts.deniedTraffic"
          :label="$t('firewallAdmin.denyAlerts')"
        />
        <FormSwitchField
          id="alert-failures"
          v-model="draft.alerts.failures"
          :label="$t('firewallAdmin.failureAlerts')"
        />
        <FormNumberField
          id="deny-threshold"
          v-model="draft.alerts.denyThreshold"
          :label="$t('firewallAdmin.denyThreshold')"
        />
      </FormGroup>
      <section class="space-y-4">
        <h2 class="text-lg font-semibold">{{ $t('firewallAdmin.groups') }}</h2>
        <FormGroup v-for="group in draft.groups" :key="group.id">
          <FormTextField
            :id="`group-name-${group.id}`"
            v-model="group.name"
            :label="$t('firewallAdmin.name')"
          />
          <label :for="`members-${group.id}`">
            {{ $t('firewallAdmin.members') }}
          </label>
          <select
            :id="`members-${group.id}`"
            v-model="group.peerIds"
            multiple
            class="ui-input min-h-32"
          >
            <option
              v-for="peer in availablePeers"
              :key="peer.id"
              :value="peer.id"
            >
              {{ peer.name }} (#{{ peer.id }})
            </option>
          </select>
          <div class="col-span-full">
            <BaseSecondaryButton type="button" @click="removeGroup(group.id)">
              {{ $t('common.actions.delete') }}
            </BaseSecondaryButton>
          </div>
        </FormGroup>
        <BaseSecondaryButton type="button" @click="addGroup">
          {{ $t('firewallAdmin.addGroup') }}
        </BaseSecondaryButton>
      </section>
      <section class="space-y-4">
        <h2 class="text-lg font-semibold">{{ $t('firewallAdmin.rules') }}</h2>
        <AdminFirewallRule
          v-for="(rule, index) in draft.rules"
          :key="rule.id"
          v-model="draft.rules[index]!"
          :groups="draft.groups"
          :peers="availablePeers"
          @remove="draft.rules.splice(index, 1)"
        />
        <BaseSecondaryButton type="button" @click="addRule">
          {{ $t('firewallAdmin.addRule') }}
        </BaseSecondaryButton>
      </section>
      <p v-if="message" role="status" class="callout">{{ message }}</p>
      <div class="flex gap-3">
        <BasePrimaryButton type="submit" :disabled="saving">
          {{ $t('common.actions.save') }}
        </BasePrimaryButton>
        <BaseSecondaryButton
          type="button"
          :disabled="saving"
          @click="reloadDraft"
        >
          {{ $t('firewallAdmin.reload') }}
        </BaseSecondaryButton>
      </div>
    </FormElement>
    <section class="surface overflow-x-auto p-4">
      <h2 class="mb-3 text-lg font-semibold">
        {{ $t('firewallAdmin.peers') }}
      </h2>
      <p class="mb-3 text-sm">{{ $t('firewallAdmin.peerHelp') }}</p>
      <table class="w-full text-left text-sm">
        <thead>
          <tr>
            <th>{{ $t('firewallAdmin.peer') }}</th>
            <th>{{ $t('firewallAdmin.status') }}</th>
            <th>{{ $t('firewallAdmin.endpoint') }}</th>
            <th>RX / TX (bytes)</th>
            <th>{{ $t('firewallAdmin.handshake') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="peer in data.peers"
            :key="peer.id"
            class="border-t border-line"
          >
            <td class="py-3">{{ peer.name }} (#{{ peer.id }})</td>
            <td>
              {{
                peer.connected
                  ? $t('firewallAdmin.online')
                  : $t('firewallAdmin.offline')
              }}
            </td>
            <td>{{ peer.endpoint ?? '—' }}</td>
            <td>{{ peer.transferRx }} / {{ peer.transferTx }}</td>
            <td>{{ peer.latestHandshakeAt ?? '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>
    <section class="surface overflow-x-auto p-4">
      <h2 class="mb-3 text-lg font-semibold">
        {{ $t('firewallAdmin.events') }}
      </h2>
      <p class="mb-3 text-sm">{{ $t('firewallAdmin.logHelp') }}</p>
      <label for="event-filter">{{ $t('firewallAdmin.filter') }}</label>
      <input
        id="event-filter"
        v-model="filter"
        class="ui-input my-3"
        type="search"
      />
      <table class="w-full text-left text-sm">
        <thead>
          <tr>
            <th>{{ $t('firewallAdmin.time') }}</th>
            <th>{{ $t('firewallAdmin.action') }}</th>
            <th>{{ $t('firewallAdmin.peer') }}</th>
            <th>{{ $t('firewallAdmin.traffic') }}</th>
            <th>{{ $t('firewallAdmin.detail') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="event in filteredEvents"
            :key="event.id"
            class="border-t border-line"
          >
            <td class="py-3">{{ event.at }}</td>
            <td>{{ event.kind }}</td>
            <td>{{ event.peerId ?? '—' }}</td>
            <td>
              {{ event.source }} → {{ event.destination }} {{ event.protocol }}
              {{ event.port }}
            </td>
            <td>
              {{ event.message }}
              {{ event.rule !== undefined ? '#' + event.rule : '' }}
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
  <p v-else role="alert">{{ error?.message }}</p>
</template>

<script setup lang="ts">
import {
  defaultFirewallPolicy,
  FirewallPolicySchema,
} from '#shared/contracts/firewall';

const { t } = useI18n();
const { data, error, refresh } = await useFetch('/api/admin/firewall');
const draft = ref(
  data.value
    ? structuredClone(toRaw(data.value.policy))
    : defaultFirewallPolicy()
);
const revision = ref(data.value?.revision ?? 0);
const saving = ref(false);
const message = ref('');
const filter = ref('');
const availablePeers = computed(() => data.value?.peers ?? []);
const filteredEvents = computed(() =>
  (data.value?.events ?? [])
    .filter((event) =>
      JSON.stringify(event).toLowerCase().includes(filter.value.toLowerCase())
    )
    .slice(0, 200)
);
useIntervalFn(() => {
  if (!saving.value) {
    void refresh();
  }
}, 15000);

async function reloadDraft() {
  await refresh();
  if (!data.value) {
    return;
  }
  draft.value = structuredClone(toRaw(data.value.policy));
  revision.value = data.value.revision;
  message.value = '';
}
async function save() {
  const parsed = FirewallPolicySchema.safeParse(draft.value);
  if (!parsed.success) {
    message.value = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    return;
  }
  saving.value = true;
  try {
    await $fetch('/api/admin/firewall', {
      method: 'POST',
      body: { revision: revision.value, policy: parsed.data },
    });
    await reloadDraft();
    message.value = t('firewallAdmin.saved');
  } catch (error) {
    const failure = error as { data?: { message?: string } };
    message.value = failure.data?.message ?? t('firewallAdmin.saveFailed');
    // Keep the draft. A host apply failure may have committed the desired revision.
    await refresh();
  } finally {
    saving.value = false;
  }
}
function createId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}
function addGroup() {
  draft.value.groups.push({
    id: createId(),
    name: t('firewallAdmin.group'),
    peerIds: [],
  });
}
function removeGroup(id: string) {
  draft.value.groups = draft.value.groups.filter((group) => group.id !== id);
  draft.value.rules = draft.value.rules.filter((rule) => rule.groupId !== id);
}
function addRule() {
  draft.value.rules.push({
    id: createId(),
    name: t('firewallAdmin.rules'),
    enabled: true,
    scope: 'global',
    peerId: null,
    groupId: null,
    priority: 100,
    action: 'DENY',
    destination: 'internet',
    targetPeerId: null,
    cidr: null,
    family: 'both',
    protocol: 'any',
    ports: null,
    log: true,
  });
}
</script>
