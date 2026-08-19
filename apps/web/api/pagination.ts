export type CursorPage<T> = {
  readonly items: readonly T[];
  readonly page_info: {
    readonly has_more: boolean;
    readonly next_cursor: string | null;
  };
};

export type LoadedCursorPages<T> = {
  readonly items: readonly T[];
  readonly pages: readonly CursorPage<T>[];
};

export async function loadAllCursorPages<T>(
  read: (cursor?: string) => Promise<CursorPage<T>>,
  bounds: { readonly maximumItems: number; readonly maximumPages: number },
): Promise<LoadedCursorPages<T>> {
  if (!Number.isSafeInteger(bounds.maximumItems) || bounds.maximumItems < 1 || !Number.isSafeInteger(bounds.maximumPages) || bounds.maximumPages < 1) {
    throw new Error("invalid pagination bounds");
  }
  const items: T[] = [];
  const pages: CursorPage<T>[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < bounds.maximumPages; pageNumber += 1) {
    const page = await read(cursor);
    pages.push(page);
    items.push(...page.items);
    if (items.length > bounds.maximumItems) throw new Error("pagination item cap exceeded");
    if (!page.page_info.has_more) return { items, pages };
    const next = page.page_info.next_cursor;
    if (!next || next === cursor || seen.has(next)) throw new Error("pagination repeated cursor");
    seen.add(next);
    cursor = next;
  }
  throw new Error("pagination page cap exceeded");
}
