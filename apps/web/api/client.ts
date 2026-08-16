import createClient from "openapi-fetch";
import type { ClientOptions } from "openapi-fetch";

import type { paths, ProductId } from "./generated";

export function createAPIClient(options: ClientOptions = {}) {
  return createClient<paths>(options);
}

export type APIClient = ReturnType<typeof createAPIClient>;
export type ProductID = ProductId;
export type { Cursor, PageInfo, ProductError } from "./generated";
