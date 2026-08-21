export async function reloadBrowserPage(cdp) {
  await cdp.send("Page.reload", { ignoreCache: true });
}
