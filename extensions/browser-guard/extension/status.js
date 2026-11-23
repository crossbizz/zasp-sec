function list(id, entries, empty) {
  const target = document.getElementById(id);
  target.replaceChildren();
  for (const entry of entries.length ? entries : [empty]) {
    const item = document.createElement("li");
    item.textContent = entry;
    target.append(item);
  }
}
async function show(input = { kind: "local-status" }) {
  const statuses = {
    unconfigured: "Managed policy required. Collection is off.",
    disabled: "Disabled by your administrator.",
    invalid: "Invalid managed settings. Ask your administrator to check the enabled origins and retention.",
    unavailable: "Managed settings unavailable. Collection is paused.",
    enabled: "Local app usage collection enabled.",
  };
  const result = await globalThis.chrome.runtime.sendMessage(input);
  if (!result?.policy) throw new Error("status unavailable");
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
    document.getElementById("destination").textContent = [central.control, central.environment, central.lastSync].filter(Boolean).join(" · ");
    document.getElementById("profile-key").value = central.publicKey ?? "";
    document.getElementById("profile-id").value = central.id ?? "";
    document.getElementById("environment").value = central.environment ?? "";
  } else document.getElementById("central-state").textContent = "Collection stays in this browser profile.";

  document.getElementById("status").textContent = statuses[policy.status];
  const uploads = result.uploads;
  document.getElementById("uploads").textContent = uploads?.status === "active"
    ? uploads.count + (uploads.count === 1 ? " exact upload route active" : " exact upload routes active") + " in this browser profile."
    : uploads?.status === "invalid" ? "No upload routes enabled. Check the managed route list."
    : uploads?.status === "unavailable" ? "Upload rule state unavailable. Recheck the managed profile."
    : "Upload blocking disabled.";
  list("origins", policy.origins, "None");
  document.getElementById("retention").textContent = policy.status === "enabled"
    ? "Retention: " + policy.retentionDays + " UTC calendar days." : "";
  list("observations", observations.map((item) => item.day + " · " + item.origin), "No recorded usage");
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
show().catch(() => {
  document.getElementById("status").textContent = "Local coverage unavailable. Check extension permissions and managed settings.";
});
