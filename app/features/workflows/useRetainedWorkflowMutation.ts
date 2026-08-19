"use client";

import { useCallback, useRef, useState } from "react";

import {
  createRetainedWorkflowMutationController,
  type WorkflowMutationAttempt,
} from "./api";

export function useRetainedWorkflowMutation<I>() {
  const controller = useRef(createRetainedWorkflowMutationController<I>()).current;
  const [hasAmbiguousAttempt, setHasAmbiguousAttempt] = useState(false);
  const settle = useCallback(async <T,>(promise: Promise<T>) => {
    try { return await promise; } finally { setHasAmbiguousAttempt(controller.hasAmbiguousAttempt()); }
  }, [controller]);
  const execute = useCallback(<T,>(intent: I, send: (frozenIntent: I, attempt: WorkflowMutationAttempt) => Promise<T>) => settle(controller.execute(intent, send)), [controller, settle]);
  const retry = useCallback(<T,>() => settle(controller.retry<T>()), [controller, settle]);
  const resolveAfterServerReconciliation = useCallback(() => {
    controller.resolveAfterServerReconciliation();
    setHasAmbiguousAttempt(false);
  }, [controller]);
  return { execute, retry, hasAmbiguousAttempt, resolveAfterServerReconciliation } as const;
}
