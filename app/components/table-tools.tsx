"use client";

import { useMemo, useState } from "react";

// Long tables are shown a page at a time, with a filter box above them. The
// rows are already loaded, so both work in the browser without a request.

export const TABLE_PAGE_SIZE = 25;

export type PagedRows<T> = Readonly<{
  rows: readonly T[];
  total: number;
  matched: number;
  page: number;
  pages: number;
  pageSize: number;
  query: string;
  setQuery(value: string): void;
  setPage(value: number): void;
}>;

// text returns what the filter box searches for one row.
export function usePagedRows<T>(items: readonly T[], text: (item: T) => string, pageSize: number = TABLE_PAGE_SIZE): PagedRows<T> {
  const [query, setQueryValue] = useState("");
  const [requestedPage, setPage] = useState(0);
  const needle = query.trim().toLowerCase();
  const matching = useMemo(() => needle === "" ? items : items.filter((item) => text(item).toLowerCase().includes(needle)), [items, needle, text]);
  const pages = Math.max(1, Math.ceil(matching.length / pageSize));
  const page = Math.min(requestedPage, pages - 1);
  const rows = useMemo(() => matching.slice(page * pageSize, (page + 1) * pageSize), [matching, page, pageSize]);
  return { rows, total: items.length, matched: matching.length, page, pages, pageSize, query, setQuery: (value) => { setQueryValue(value); setPage(0); }, setPage };
}

export function TableFilter<T>({ paged, label, placeholder }: { paged: PagedRows<T>; label: string; placeholder: string }) {
  if (paged.total <= 8) return null;
  return <div className="table-toolbar">
    <input type="search" className="table-filter" aria-label={label} placeholder={placeholder} value={paged.query} maxLength={128} onChange={(event) => paged.setQuery(event.target.value)} />
    <span className="table-count" role="status">{paged.query.trim() === "" ? `${paged.total} total` : `${paged.matched} of ${paged.total} match`}</span>
  </div>;
}

export function TablePagination<T>({ paged, label }: { paged: PagedRows<T>; label: string }) {
  if (paged.matched === 0) return paged.query.trim() === "" ? null : <p className="table-empty">Nothing matches “{paged.query.trim()}”.</p>;
  if (paged.pages <= 1) return null;
  const first = paged.page * paged.pageSize + 1;
  const last = Math.min(paged.matched, (paged.page + 1) * paged.pageSize);
  return <nav className="table-pagination" aria-label={`${label} pages`}>
    <span>{first}–{last} of {paged.matched}</span>
    <span className="table-pagination__controls">
      <button type="button" className="button button--secondary" disabled={paged.page === 0} onClick={() => paged.setPage(paged.page - 1)}>Previous</button>
      <span aria-current="page">Page {paged.page + 1} of {paged.pages}</span>
      <button type="button" className="button button--secondary" disabled={paged.page >= paged.pages - 1} onClick={() => paged.setPage(paged.page + 1)}>Next</button>
    </span>
  </nav>;
}
