// The service worker validates the browser-provided top-level origin.
globalThis.chrome.runtime.sendMessage({ kind: "origin-seen" }).catch(() => {});
