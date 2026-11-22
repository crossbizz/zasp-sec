import { createGuard } from "./guard.mjs";

import { createReporting } from "./reporting.mjs";

const guard = createGuard(chrome);
const reporting = createReporting();
let pending = Promise.resolve();
function serialize(task) {
  const result = pending.then(task);
  pending = result.catch(() => {});
  return result;
}
async function start() {
  await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  await chrome.storage.managed.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  await chrome.alarms.create("zasp-retention", { periodInMinutes: 60 });
  const { policy } = await guard.refresh();
  return reporting.sync(policy);
}
chrome.runtime.onInstalled.addListener(() => { serialize(start); });
chrome.runtime.onStartup.addListener(() => { serialize(start); });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "zasp-retention") serialize(start);
});
chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "managed") serialize(start);
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.kind === "origin-seen") {
    serialize(async () => {
      const seen = await guard.observe(sender);
      if (seen) await reporting.observe(seen.policy, seen.observation);
    }).then(() => reply({}), () => reply({}));
  } else if (["local-status", "profile-enroll", "profile-remove", "profile-sync"].includes(message?.kind) && sender.id === chrome.runtime.id &&
      sender.url === chrome.runtime.getURL("status.html") && !sender.tab?.incognito) {
    serialize(async () => {
      const local = await guard.refresh();
      let central;
      if (message.kind === "profile-enroll") central = await reporting.enroll(local.policy, message.id, message.environment, message.token);
      else if (message.kind === "profile-remove") central = await reporting.remove();
      else if (message.kind === "profile-sync") central = await reporting.sync(local.policy);
      else central = await reporting.status(local.policy);
      return { ...local, central };
    }).then(reply, () => reply({ error: "unavailable" }));
  } else {
    return false;
  }
  return true;
});
serialize(start);
