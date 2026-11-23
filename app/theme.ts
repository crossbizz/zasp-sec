export const themeCookie = "zasp.theme";

export const themeBootstrap = `(() => { try { const choice = document.cookie.match(/(?:^|; )zasp\\.theme=(dark|light)(?:;|$)/); document.documentElement.dataset.theme = choice?.[1] ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); } catch { document.documentElement.dataset.theme = "light"; } })();`;
