"use client";

import { createContext, createElement, type ReactNode, useCallback, useContext, useMemo, useReducer, useState } from "react";

import {
  createRetainedWorkflowMutationController,
  type WorkflowMutationAttempt,
} from "./api";

type WorkflowMutationRegistry = {
  scopeKey: string;
  get<I>(operationKey: string): ReturnType<typeof createRetainedWorkflowMutationController<I>>;
};

const WorkflowMutationRegistryContext = createContext<WorkflowMutationRegistry | null>(null);

export function WorkflowMutationProvider({ scopeKey, children }: { scopeKey: string; children: ReactNode }) {
  const [controllers] = useState(() => new Map<string, ReturnType<typeof createRetainedWorkflowMutationController<unknown>>>());
  const value = useMemo<WorkflowMutationRegistry>(() => ({
    scopeKey,
    get<I>(operationKey: string) {
      if (!scopeKey || !operationKey) throw new Error("Workflow mutation scope and operation keys are required");
      const registryKey = JSON.stringify([scopeKey, operationKey]);
      let controller = controllers.get(registryKey);
      if (!controller) {
        controller = createRetainedWorkflowMutationController<unknown>();
        controllers.set(registryKey, controller);
      }
      return controller as ReturnType<typeof createRetainedWorkflowMutationController<I>>;
    },
  }), [controllers, scopeKey]);
  return createElement(WorkflowMutationRegistryContext.Provider, { value }, children);
}

export function useRetainedWorkflowMutation<I>(operationKey = "component-local") {
  const registry = useContext(WorkflowMutationRegistryContext);
  const [localController] = useState(() => createRetainedWorkflowMutationController<I>());
  const controller = registry?.get<I>(operationKey) ?? localController;
  const [, refresh] = useReducer((value: number) => value + 1, 0);
  const settle = useCallback(async <T,>(promise: Promise<T>) => {
    try { return await promise; } finally { refresh(); }
  }, [controller]);
  const execute = useCallback(<T,>(intent: I, send: (frozenIntent: I, attempt: WorkflowMutationAttempt) => Promise<T>) => settle(controller.execute(intent, send)), [controller, settle]);
  const retry = useCallback(<T,>() => settle(controller.retry<T>()), [controller, settle]);
  const resolveAfterServerReconciliation = useCallback(() => {
    controller.resolveAfterServerReconciliation();
    refresh();
  }, [controller]);
  return { execute, retry, hasAmbiguousAttempt: controller.hasAmbiguousAttempt(), resolveAfterServerReconciliation } as const;
}
