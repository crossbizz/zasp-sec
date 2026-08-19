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

export function useAPIQuery<T>(key: string, query: () => Promise<T>, enabled = true): QueryState<T> {
  const { revisions, sessionExpiry } = useAPI();
  const revision = revisions.get(key) ?? 0;
  const data = useRef<T | undefined>(undefined);
  const request = useRef(0);
  const [state, setState] = useState<Omit<QueryState<T>, "retry">>({ status: enabled ? "loading" : "idle" });
  const load = useCallback(async () => {
    if (!enabled) {
      return;
    }
    const current = ++request.current;
    try {
      const value = await query();
      if (request.current !== current) return;
      data.current = value;
      setState({ status: isEmpty(value) ? "empty" : "success", data: value });
    } catch (error) {
      if (request.current !== current) return;
	  if (isProtectedFailure(error)) {
		data.current = undefined;
		setState({ status: "forbidden", error });
	  } else if (data.current !== undefined) {
        setState({ status: "stale", data: data.current, error });
      } else {
        setState({ status: isForbidden(error) ? "forbidden" : "error", error });
      }
    }
  }, [enabled, query]);
  const retry = useCallback(async () => {
    if (!enabled) {
      setState({ status: "idle" });
      return;
    }
    if (data.current === undefined) setState({ status: "loading" });
    await load();
  }, [enabled, load]);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => { if (active) void load(); });
    return () => { active = false; request.current += 1; };
  }, [load, revision, sessionExpiry]);
  return { ...state, retry };
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
