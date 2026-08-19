"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useAPI } from "./APIProvider";

export type QueryStatus = "idle" | "loading" | "empty" | "success" | "stale" | "forbidden" | "error";

export type QueryState<T> = {
  status: QueryStatus;
  data?: T;
  error?: unknown;
  retry(): Promise<void>;
};

type StoredQueryState<T> = Omit<QueryState<T>, "retry"> & { epoch: string };

export function useAPIQuery<T>(key: string, query: (signal?: AbortSignal) => Promise<T>, enabled = true): QueryState<T> {
	const { revisions, queryScopeKey, queryGeneration } = useAPI();
  const revision = revisions.get(key) ?? 0;
  const epoch = JSON.stringify([queryScopeKey, queryGeneration, key]);
  const queryEnabled = enabled && queryScopeKey !== null;
  const data = useRef<{ epoch: string; value: T } | undefined>(undefined);
  const request = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const [state, setState] = useState<StoredQueryState<T>>({ epoch, status: queryEnabled ? "loading" : "idle" });
  const load = useCallback(async () => {
    if (!queryEnabled) {
      setState({ epoch, status: "idle" });
      return;
    }
    const current = ++request.current;
    controller.current?.abort();
    const currentController = new AbortController();
    controller.current = currentController;
    try {
      const value = await query(currentController.signal);
      if (currentController.signal.aborted || request.current !== current) return;
      data.current = { epoch, value };
      setState({ epoch, status: isEmpty(value) ? "empty" : "success", data: value });
    } catch (error) {
      if (currentController.signal.aborted || request.current !== current) return;
	  if (isProtectedFailure(error)) {
		data.current = undefined;
		setState({ epoch, status: "forbidden", error });
	  } else if (data.current?.epoch === epoch) {
        setState({ epoch, status: "stale", data: data.current.value, error });
      } else {
        setState({ epoch, status: isForbidden(error) ? "forbidden" : "error", error });
      }
    }
  }, [epoch, queryEnabled, query]);
  const retry = useCallback(async () => {
    if (!queryEnabled) {
      setState({ epoch, status: "idle" });
      return;
    }
    if (data.current?.epoch !== epoch) setState({ epoch, status: "loading" });
    await load();
  }, [epoch, queryEnabled, load]);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void load(); });
    return () => {
      active = false;
      request.current += 1;
      controller.current?.abort();
    };
	}, [load, revision, queryGeneration]);
  const visibleState: Omit<QueryState<T>, "retry"> = queryEnabled && state.epoch === epoch
    ? state
    : { status: queryEnabled ? "loading" : "idle" };
  return { ...visibleState, retry };
}

export type MutationState<TResult> = {
  status: "idle" | "loading" | "success" | "error";
  data?: TResult;
  error?: unknown;
  run(): Promise<TResult>;
};

export function useAPIMutation<TResult>(mutation: () => Promise<TResult>, invalidates: readonly string[]): MutationState<TResult> {
  const { invalidate } = useAPI();
  const [state, setState] = useState<Omit<MutationState<TResult>, "run">>({ status: "idle" });
  const run = useCallback(async () => {
    setState({ status: "loading" });
    try {
      const value = await mutation();
      setState({ status: "success", data: value });
      invalidate(invalidates);
      return value;
    } catch (error) {
      setState({ status: "error", error });
      throw error;
    }
  }, [mutation, invalidate, invalidates]);
  return { ...state, run };
}

function isEmpty(value: unknown): boolean {
  if (value == null) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object" && "items" in value && Array.isArray((value as { items: unknown }).items)) {
    return (value as { items: readonly unknown[] }).items.length === 0;
  }
  return false;
}

function isForbidden(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const response = (error as { response?: { status?: unknown } }).response;
  const product = (error as { error?: { code?: unknown } }).error;
  return response?.status === 403 || product?.code === "authorization_rejected";
}

function isProtectedFailure(error: unknown): boolean {
	if (isForbidden(error)) return true;
	if (!error || typeof error !== "object") return false;
	const response = (error as { response?: { status?: unknown }; status?: unknown }).response;
	const status = response?.status ?? (error as { status?: unknown }).status;
	const product = (error as { error?: { code?: unknown }; product?: { code?: unknown } }).error ?? (error as { product?: { code?: unknown } }).product;
	return status === 401 || product?.code === "authentication_required";
}
