// The SDK uses browser fetch internally. Bound each request and retain only safe
// endpoint metadata; never record auth URLs, headers, request bodies or responses.
export function installNetworkGuard({
  signal,
  onEvent,
  timeoutMs = 15000,
  relayOrigin,
}) {
  const original = globalThis.fetch;
  const pending = new Set();
  const events = [];
  let failure;
  const classify = (url) =>
    url.origin === relayOrigin
      ? "relay"
      : url.pathname.includes("/auth/")
        ? "homeserver"
        : url.hostname.includes("pkarr")
          ? "discovery"
          : "network";
  const guarded = async (input, init = {}) => {
    if (signal.aborted) throw signal.reason;
    const request = input instanceof Request ? input : undefined;
    const url = new URL(
      request ? request.url : String(input),
      globalThis.location?.href,
    );
    const phase = classify(url);
    const event = {
      phase,
      origin: url.origin,
      method: init.method || request?.method || "GET",
    };
    events.push(event);
    if (events.length > 40) events.shift();
    onEvent(event);
    const controller = new AbortController();
    const inherited = init.signal || request?.signal;
    const abort = () => controller.abort(signal.reason);
    const inherit = () => controller.abort(inherited.reason);
    signal.addEventListener("abort", abort, { once: true });
    inherited?.addEventListener("abort", inherit, { once: true });
    if (inherited?.aborted) inherit();
    const cleanup = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      inherited?.removeEventListener("abort", inherit);
      pending.delete(entry);
    };
    const timer = setTimeout(() => {
      controller.abort(
        new DOMException("Network request timed out", "TimeoutError"),
      );
      cleanup();
    }, timeoutMs);
    const entry = { controller, cleanup };
    pending.add(entry);
    try {
      const response = await original.call(globalThis, input, {
        ...init,
        signal: controller.signal,
      });
      event.status = response.status;
      // Keep cancellation active while the SDK consumes a successful body.
      // The bounded timer also aborts stalled body reads, then removes listeners.
      if (!response.body) cleanup();
      onEvent(event);
      if (!response.ok && response.status !== 404)
        failure = { ...event, kind: "http" };
      return response;
    } catch (error) {
      if (!signal.aborted)
        failure = {
          ...event,
          kind:
            controller.signal.reason?.name === "TimeoutError"
              ? "timeout"
              : "network",
        };
      cleanup();
      throw error;
    }
  };
  globalThis.fetch = guarded;
  return {
    events,
    get failure() {
      return failure;
    },
    dispose() {
      for (const entry of [...pending]) {
        entry.controller.abort();
        entry.cleanup();
      }
      if (globalThis.fetch === guarded) globalThis.fetch = original;
    },
  };
}
