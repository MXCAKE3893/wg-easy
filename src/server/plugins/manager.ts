import { defineNitroPlugin } from 'nitropack/runtime';

import { connect } from '#db/sqlite';
import { setDatabase } from '#db';
import * as vpn from '#server/features/vpn/lifecycle';
import { initialize } from '#server/features/setup';
import { startMaintenance } from '#server/jobs/maintenance';
import { startSecurityMonitor } from '#server/features/firewall/monitor';
import { recordEvent } from '#server/features/firewall/runtime';
import { RELEASE, OLD_ENV, WG_ENV, WG_INITIAL_ENV } from '#server/utils/config';

export default defineNitroPlugin(async (nitroApp) => {
  console.log(`
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   wg-easy - https://github.com/wg-easy/wg-easy   ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ wg-easy:  ${RELEASE.padEnd(38)} ┃
┃ Node:     ${process.version.padEnd(38)} ┃
┃ Platform: ${process.platform.padEnd(38)} ┃
┃ Arch:     ${process.arch.padEnd(38)} ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
`);
  if (OLD_ENV.PASSWORD || OLD_ENV.PASSWORD_HASH) {
    throw new Error(
      'You are using an invalid Configuration for wg-easy. Please follow https://wg-easy.github.io/wg-easy/latest/advanced/migrate/from-14-to-15/ to migrate.'
    );
  }
  const database = await connect({
    interfaceName: WG_ENV.WG_INTERFACE,
    disableIpv6: WG_ENV.DISABLE_IPV6,
  });
  setDatabase(database.store);
  try {
    if (WG_INITIAL_ENV.ENABLED) {
      await initialize({
        username: WG_INITIAL_ENV.USERNAME,
        password: WG_INITIAL_ENV.PASSWORD,
        host: WG_INITIAL_ENV.HOST,
        port: WG_INITIAL_ENV.PORT,
        ipv4Cidr: WG_INITIAL_ENV.IPV4_CIDR,
        ipv6Cidr: WG_INITIAL_ENV.IPV6_CIDR,
        dns: WG_INITIAL_ENV.DNS,
        allowedIps: WG_INITIAL_ENV.ALLOWED_IPS,
      });
    }
    await vpn.start();
  } catch (error) {
    await vpn.stop().catch(() => {});
    database.close();
    throw error;
  }
  const stopSecurityMonitor = startSecurityMonitor();
  let maintenanceFailed = false;
  const stopMaintenance = startMaintenance(async () => {
    try {
      await vpn.maintain();
      if (maintenanceFailed) {
        recordEvent({ kind: 'recovery', message: 'VPN maintenance recovered' });
      }
      maintenanceFailed = false;
    } catch (error) {
      if (!maintenanceFailed) {
        recordEvent({
          kind: 'failure',
          message: 'VPN maintenance failed; automatic retry pending',
        });
      }
      maintenanceFailed = true;
      throw error;
    }
  });
  nitroApp.hooks.hook('close', async () => {
    console.log('Shutting down');
    await stopMaintenance();
    await stopSecurityMonitor();
    try {
      await vpn.stop();
    } finally {
      database.close();
    }
  });
});
