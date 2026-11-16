const preferenceKey = "zasp.theme";

export const themeBootstrap = `(() => { try { const saved = localStorage.getItem("${preferenceKey}"); document.documentElement.dataset.theme = saved === "dark" || saved === "light" ? saved : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; } catch { document.documentElement.dataset.theme = "light"; } })();`;
