export async function reloadBrowserPage(cdp) {
  await cdp.send("Page.reload", { ignoreCache: true });
}

// These functions also run inside Chrome via Runtime.evaluate.
export function readComplianceSourceDetail(document) {
  const card = document.querySelector("section.evidence-source");
  if (!card) return null;
  const fields = Object.fromEntries([...card.querySelectorAll("dt")].map(term =>
    [term.textContent, term.nextElementSibling]));
  return {
    id: fields["Source ID"]?.textContent,
    version: fields.Version?.textContent,
    recorded: fields.Recorded?.querySelector("time")?.dateTime,
    freshness: card.querySelector(".card__header .badge")?.textContent,
  };
}

export function revealComplianceExport(document, viewportHeight) {
  const button = [...document.querySelectorAll("button")].find(el => el.textContent.trim() === "Create evidence export");
  if (!button) return false;
  button.scrollIntoView({block: "center", behavior: "instant"});
  const box = button.getBoundingClientRect();
  return box.height > 0 && box.width > 0 && box.top >= 0 && box.bottom <= viewportHeight;
}
