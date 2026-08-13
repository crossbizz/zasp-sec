import { env } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

export function getDb() {
  const bindings = env as unknown as { DB?: D1Database };
  if (!bindings.DB) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Configure it in your Cloudflare deployment or set CLOUDFLARE_D1_BINDING=DB for local development."
    );
  }

  return drizzle(bindings.DB, { schema });
}
