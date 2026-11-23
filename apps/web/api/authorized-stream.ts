// Keep byte and scope checks active until EOF. An SSE response may outlive
// the HTTP header timeout; stop reading as soon as its caller disconnects.
export function boundedUIMessageStream(response: Response, maxBytes: number, signal: AbortSignal, isCurrent: () => boolean): Response {
  const mime = response.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase();
  if (response.redirected || response.status !== 200 || !response.body || mime !== "text/event-stream" ||
      response.headers.get("Cache-Control") !== "no-store" || response.headers.get("x-vercel-ai-ui-message-stream") !== "v1") {
    void response.body?.cancel();
    throw new TypeError("Invalid investigation stream response");
  }
  const reader = response.body.getReader();
  let count = 0;
  let ended = false;
  let streamController: ReadableStreamDefaultController<Uint8Array>;
  const close = (reason?: unknown) => {
    if (ended) return;
    ended = true;
    signal.removeEventListener("abort", abort);
    if (reason !== undefined) {
      void reader.cancel(reason).catch(() => undefined);
      streamController.error(reason);
    }
  };
  const abort = () => close(signal.reason ?? new DOMException("Aborted", "AbortError"));
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    },
    async pull(controller) {
      try {
        if (!isCurrent()) throw new Error("Investigation scope changed");
        const { done, value } = await reader.read();
        if (ended) return;
        if (!isCurrent()) throw new Error("Investigation scope changed");
        if (done) { close(); controller.close(); return; }
        count += value.byteLength;
        if (count > maxBytes) throw new RangeError("Investigation stream exceeds its response limit");
        controller.enqueue(value);
      } catch (error) { close(error); }
    },
    async cancel(reason) { close(); await reader.cancel(reason); },
  });
  return new Response(stream, { status: response.status, headers: response.headers });
}
