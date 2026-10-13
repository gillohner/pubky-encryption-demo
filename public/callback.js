const params = new URLSearchParams(location.search);
const outcome = params.get("outcome"),
  runId = params.get("run");
if (["success", "cancel", "error"].includes(outcome) && runId) {
  document.getElementById("heading").textContent =
    outcome === "success"
      ? "Approval sent. Return to your test tab."
      : "Authorization ended. Return to your test tab.";
  if (window.opener && !window.opener.closed) {
    window.addEventListener("message", (event) => {
      if (
        event.origin === location.origin &&
        event.source === window.opener &&
        event.data?.type === "pubky-encryption-return-ack" &&
        event.data.runId === runId
      )
        window.close();
    });
    window.opener.postMessage(
      { type: "pubky-encryption-return", outcome, runId },
      location.origin,
    );
  }
}
history.replaceState(null, "", location.pathname);
