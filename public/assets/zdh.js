// zdh demo page. No build step, no bundler, no dependency — the same rule the
// server is under. Everything reported here is read out of the browser's own
// Resource Timing entries or out of a response status, so nothing on the page
// is the server's word for its own behaviour.

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// This page's own resources, as the browser recorded them.

// A resource served from the same connection reports connectStart === connectEnd,
// because no connection was opened for it. That is how the table below can say
// "reused" without asking the server anything.
function fresh(e) {
  return e.connectEnd > e.connectStart;
}

function protoTag(p) {
  const cls = p === "h2" ? "h2" : "other";
  return `<span class="tag ${cls}">${p || "—"}</span>`;
}

// responseEnd - startTime rather than entry.duration: for a resource the two are
// the same, but a navigation entry's duration runs to loadEventEnd, which is not
// settled while the load handler that calls this is still running. It would
// report 0.0 for the document and nothing else.
function fill(rows) {
  const body = $("resources").tBodies[0];
  body.innerHTML = rows
    .map(
      (e) => `<tr>
        <td title="${e.name}">${new URL(e.name).pathname}</td>
        <td>${protoTag(e.nextHopProtocol)}</td>
        <td>${e.initiatorType}${fresh(e) ? "" : " · reused"}</td>
        <td class="n">${e.encodedBodySize || e.transferSize || 0}</td>
        <td class="n">${(e.responseEnd - e.startTime).toFixed(1)}</td>
      </tr>`
    )
    .join("");
}

// A multiplexing probe carries ?stream=; a resource this page actually needs
// does not. The table is titled "this page's own resources" and that is what it
// holds — sixty-four probes belong in the multiplexing card, counted, not
// enumerated one per row.
function ownResource(e) {
  return !new URL(e.name).searchParams.has("stream");
}

function showOwnResources() {
  const nav = performance.getEntriesByType("navigation");
  const res = performance.getEntriesByType("resource").filter(ownResource);
  fill([...nav, ...res]);
}

// ---------------------------------------------------------------------------
// Multiplexing: n requests at once, on the connection this page arrived on.

async function multiplex(n) {
  $("run").disabled = $("more").disabled = true;
  $("count").value = n;

  // A distinct query per request so nothing is answered from cache. The query
  // is not part of the file name — the server drops it before the target
  // becomes a path — so all n of these are the same file and n distinct
  // requests.
  const stamp = Date.now();
  const urls = Array.from(
    { length: n },
    (_, i) => `/assets/logo.svg?stream=${i}&t=${stamp}`
  );

  const before = performance.getEntriesByType("resource").length;
  const t0 = performance.now();
  const responses = await Promise.all(urls.map((u) => fetch(u, { cache: "no-store" })));
  await Promise.all(responses.map((r) => r.arrayBuffer()));
  const wall = performance.now() - t0;

  const entries = performance.getEntriesByType("resource").slice(before);
  const protocols = new Set(entries.map((e) => e.nextHopProtocol).filter(Boolean));
  const opened = entries.filter(fresh).length;
  const slowest = entries.reduce((m, e) => Math.max(m, e.duration), 0);
  const failed = responses.filter((r) => !r.ok).length;

  $("result").hidden = false;
  $("r-total").textContent = `${n}${failed ? ` (${failed} not ok)` : ""}`;
  $("r-proto").innerHTML = [...protocols].map(protoTag).join(" ") || "—";
  $("r-conns").textContent = opened === 0 ? "0 — every one reused this page's" : opened;
  $("r-wall").textContent = `${wall.toFixed(0)} ms`;
  $("r-max").textContent = `${slowest.toFixed(1)} ms`;
  $("r-note").textContent =
    opened === 0
      ? `${n} requests interleaved on one TCP connection and one TLS handshake. Over HTTP/1.1 the same page would have needed ${Math.ceil(n / 6)} rounds on six connections.`
      : `${opened} of ${n} opened a connection of their own, which is what a browser does when a connection is at its stream limit.`;

  $("run").disabled = $("more").disabled = false;
}

// ---------------------------------------------------------------------------
// What the server refuses, and the control that proves the refusal is the rule
// and not an absent file.

const refusals = [
  ["/assets/zdh.css", "the control: an ordinary file, served"],
  ["/assets%2Fzdh.css", "%2F is not a separator — the same file, refused"],
  ["/assets/zdh.css%20", "a trailing space Win32 would strip, reaching the file above"],
  ["/assets/zdh.css.", "a trailing dot Win32 would strip, reaching it too"],
  ["/.dotfile-you-cannot-fetch.txt", "a dotfile that is really there"],
  ["/NUL", "a Win32 device name, refused on every platform"],
  ["/%2e%2e/%2e%2e/go.mod", "an encoded traversal out of the served directory"],
  ["/" + "a".repeat(5000), "a target past the length bound"],
];

async function showRefusals() {
  const body = $("refusals").tBodies[0];

  for (const [target, why] of refusals) {
    const row = body.insertRow();
    const shown = target.length > 44 ? target.slice(0, 41) + "..." : target;
    row.insertCell().textContent = shown;
    const status = row.insertCell();
    status.textContent = "…";
    row.insertCell().textContent = why;

    try {
      const r = await fetch(target, { cache: "no-store", redirect: "manual" });
      status.innerHTML = `<span class="tag ${r.status === 200 ? "h2" : "other"}">${r.status}</span>`;
    } catch (err) {
      status.textContent = "network error";
    }
  }

  // One method rather than one target, and the field §15.5.6 requires with it.
  const row = body.insertRow();
  row.insertCell().textContent = "POST /";
  const status = row.insertCell();
  const r = await fetch("/", { method: "POST", body: "x", cache: "no-store" });
  status.innerHTML = `<span class="tag other">${r.status}</span>`;
  row.insertCell().textContent = `a method this server has no answer for — allow: ${r.headers.get("allow")}`;
}

// ---------------------------------------------------------------------------

$("run").addEventListener("click", () => multiplex(64));
$("more").addEventListener("click", () => multiplex(256));

// Deferred a frame, so the entries for this page's own stylesheet and icon are
// recorded before they are read.
addEventListener("load", () => {
  showOwnResources();
  showRefusals();

  // ?run=N runs the multiplexing demonstration on load, so the result can be
  // linked to directly instead of described. Anything unparseable is ignored
  // rather than clamped to a default, so a typo shows nothing instead of
  // quietly showing the wrong number.
  const n = Number(new URLSearchParams(location.search).get("run"));
  if (Number.isInteger(n) && n > 0 && n <= 1024) multiplex(n);
});
