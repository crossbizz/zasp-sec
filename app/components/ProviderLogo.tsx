import { Cloud, Plug, Webhook, Database, Container, KeyRound } from "lucide-react";

// These local, already-sized SVG marks do not benefit from raster image optimization.
/* eslint-disable @next/next/no-img-element */

function providerAsset(provider: string) {
  const name = provider.toLowerCase();
  if (/aws|amazon/.test(name)) return "aws";
  if (/azure|microsoft|entra|copilot/.test(name)) return "azure";
  if (/gcp|google/.test(name)) return "gcp";
  if (/github/.test(name)) return "github";
  if (/openai/.test(name)) return "openai";
  if (/anthropic|claude/.test(name)) return "anthropic";
  if (/mcp/.test(name)) return "mcp";
  for (const brand of ["kubernetes", "okta", "salesforce", "slack", "gitlab", "atlassian", "databricks"]) {
    if (name.includes(brand)) return brand;
  }
  return null;
}

/** Brand artwork has its own sizing and never inherits UI icon stroke rules. */
export function ProviderLogo({ provider }: { provider: string }) {
  const asset = providerAsset(provider);
  const Fallback = /kubernetes|runtime/.test(provider) ? Container : /webhook/.test(provider) ? Webhook : /okta|identity/.test(provider) ? KeyRound : /data/.test(provider) ? Database : /saas/.test(provider) ? Plug : Cloud;
  return <span className={`provider-logo${asset ? ` provider-logo--${asset}` : ""}`} aria-hidden="true">
    {asset ? <>
      <img className="provider-logo__light" src={`/icons/providers/${asset}.svg`} width={20} height={20} alt="" />
      {["aws", "github", "openai", "mcp"].includes(asset) && <img className="provider-logo__dark" src={`/icons/providers/${asset}-dark.svg`} width={20} height={20} alt="" />}
    </> : <Fallback className="resource-glyph" size={18} strokeWidth={1.8} />}
  </span>;
}
