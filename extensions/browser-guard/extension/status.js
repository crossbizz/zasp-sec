function list(id, entries, empty) {
  const target = document.getElementById(id);
  target.replaceChildren();
  for (const entry of entries.length ? entries : [empty]) {
    const item = document.createElement("li");
    item.textContent = entry;
    target.append(item);
  }
}
function profileDetail(id, value) {
  const field = document.getElementById(id);
  field.textContent = value || "";
  field.parentElement.hidden = !value;
}
async function show(input = { kind: "local-status" }) {
  const statuses = {
    unconfigured: "Managed policy required. Collection is off.",
    disabled: "Disabled by your administrator.",
    invalid: "Invalid managed settings. Ask your administrator to check the enabled origins and retention.",
    unavailable: "Managed settings unavailable. Collection is paused.",
    enabled: "Local app usage collection enabled.",
  };
  const result = await globalThis.chrome?.runtime?.sendMessage(input);
  if (!result?.policy || !Object.hasOwn(statuses, result.policy.status) ||
      !Array.isArray(result.policy.origins) || !Array.isArray(result.observations)) throw new Error("status unavailable");
  const { policy, observations, central } = result;
  const remote = central && !["local_only", "removed"].includes(central.state);
  const panel = document.getElementById("profile");
  panel.hidden = !remote;
  if (remote) {
    const states = {
      awaiting_registration: "Awaiting profile enrollment. Collection is local.",
      awaiting_acknowledgment: "Awaiting an acknowledgment from Zasp.",
      reporting: "Zasp accepted this managed profile’s latest sync.",
      authorization_required: "Authorization stopped. Verify the profile key, token, Environment and approved origins.",
      offline: "Zasp is unavailable. The profile will retry at the next scheduled sync.",
    };
    document.getElementById("central-state").textContent = states[central.state] ?? "Managed profile status unavailable.";
    profileDetail("destination", central.control);
    profileDetail("bound-environment", central.environment);
    profileDetail("last-sync", central.lastSync);
    document.getElementById("profile-key").value = central.publicKey ?? "";
    document.getElementById("profile-id").value = central.id ?? "";
    document.getElementById("environment").value = central.environment ?? "";
  } else document.getElementById("central-state").textContent = !central && policy.remoteEnabled
    ? "Managed profile reporting status unavailable." : "Collection stays in this browser profile.";

  document.getElementById("status").textContent = statuses[policy.status];
  const uploads = result.uploads;
  document.getElementById("uploads").textContent = uploads?.status === "active"
    ? uploads.count + (uploads.count === 1 ? " exact upload route active" : " exact upload routes active") + " in this browser profile."
    : uploads?.status === "invalid" ? "No upload routes enabled. Check the managed route list."
    : uploads?.status === "unavailable" ? "Upload rule state unavailable. Recheck the managed profile."
    : "Upload blocking disabled.";
  list("origins", policy.origins, "No enabled apps");
  document.getElementById("retention").hidden = policy.status !== "enabled";
  document.getElementById("retention").textContent = policy.status === "enabled"
    ? "Retained for " + policy.retentionDays + (policy.retentionDays === 1 ? " UTC calendar day." : " UTC calendar days.") : "";
  list("observations", observations.map((item) => item.day + " · " + item.origin), "No recorded usage");
  document.getElementById("central-state").hidden = false;
  document.getElementById("coverage").hidden = false;
  document.getElementById("guidance").hidden = true;
  document.getElementById("retry").hidden = true;
}
function command(input) {
  return show(input).catch(() => { document.getElementById("central-state").textContent = "Could not update enrollment. Verify the profile settings."; });
}
document.getElementById("enroll-profile").addEventListener("submit", (event) => {
  event.preventDefault();
  const token = document.getElementById("profile-token");
  const value = token.value;
  token.value = "";
  command({ kind: "profile-enroll", id: document.getElementById("profile-id").value.trim(), environment: document.getElementById("environment").value.trim(), token: value });
});
document.getElementById("profile-sync").addEventListener("click", () => command({ kind: "profile-sync" }));
document.getElementById("profile-remove").addEventListener("click", () => command({ kind: "profile-remove" }));
async function readStatus() {
  const retry = document.getElementById("retry");
  retry.disabled = true;
  try {
    await show();
  } catch {
    const canRetry = typeof globalThis.chrome?.runtime?.sendMessage === "function";
    document.getElementById("status").textContent = "Local coverage unavailable.";
    document.getElementById("central-state").hidden = true;
    document.getElementById("coverage").hidden = true;
    const guidance = document.getElementById("guidance");
    guidance.textContent = canRetry ? "Check extension permissions and managed settings, then retry."
      : "Open Zasp Browser Guard from your browser toolbar to check this profile’s coverage.";
    guidance.hidden = false;
    retry.hidden = !canRetry;
  } finally {
    retry.disabled = false;
  }
}
document.getElementById("retry").addEventListener("click", readStatus);
readStatus();
