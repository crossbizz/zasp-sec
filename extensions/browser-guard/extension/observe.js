// The service worker validates the browser-provided top-level origin.
chrome.runtime.sendMessage({ kind: "origin-seen" }).catch(() => {});
