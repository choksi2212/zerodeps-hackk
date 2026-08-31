// zdh demo page. No build step, no bundler, no dependency — the same rule the
// server is under. Everything reported here is read out of the browser's own
// Resource Timing entries or out of a response status, so nothing on the page
// is the server's word for its own behaviour.

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// Hero: the protocol chip is filled from this page's own navigation entry, so
// even the headline number is the browser's word rather than the server's.

function showHero() {
  const nav = performance.getEntriesByType("navigation")[0];
  if (nav && nav.nextHopProtocol) $("hero-proto").textContent = nav.nextHopProtocol;
}

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
// holds — sixty-four probes belong in the live card, drawn, not enumerated one
// per row.
function ownResource(e) {
  return !new URL(e.name).searchParams.has("stream");
}

function showOwnResources() {
  const nav = performance.getEntriesByType("navigation");
  const res = performance.getEntriesByType("resource").filter(ownResource);
  fill([...nav, ...res]);
}

// ---------------------------------------------------------------------------
// The frame ticker: names the frame types this exchange is made of. These are
// the frames HTTP/2 sends for a batch of GETs — a client HEADERS per request, a
// server HEADERS and DATA per response — labelled by kind. It is a narration of
// the protocol, drawn from what was requested and what came back, not a capture
// off the wire.

function tick(kind, text) {
  const t = $("ticker");
  const line = document.createElement("div");
  line.className = "frame " + kind;
  line.innerHTML = text;
  t.appendChild(line);
  // keep the column bounded; column-reverse means newest sits at the bottom edge
  while (t.childElementCount > 60) t.removeChild(t.firstChild);
}

// ---------------------------------------------------------------------------
// Live multiplexing: n requests at once, on the connection this page arrived on,
// each drawn as a bar the moment it resolves. The bars share one lane strip with
// a left edge that stands for the single connection — dozens of them stacking and
// overlapping is the multiplexing, made visible.

const LANE_H = 240;

function placeBar(i, n, entry, t0) {
  const lanes = $("lanes");
  const bar = document.createElement("div");
  bar.className = "bar";
  // vertical position: spread the n requests down the strip
  const top = Math.round((i / n) * (LANE_H - 6));
  // horizontal: start offset and width scaled from the request's own timing,
  // relative to the batch wall clock so the picture fills the strip
  const start = Math.max(0, entry ? entry.startTime - t0 : 0);
  const dur = entry ? Math.max(2, entry.duration) : 4;
  const scale = 0.9 / Math.max(1, batchSpan());
  bar.style.top = top + "px";
  bar.style.left = (2 + start * scale * 100) + "%";
  bar.style.width = Math.min(96, dur * scale * 100) + "%";
  lanes.appendChild(bar);
  // flip to "done" green a beat later, so the eye catches the completion
  setTimeout(() => bar.classList.add("done"), 120);
  return bar;
}

let _batchSpan = 100;
function batchSpan() { return _batchSpan; }

async function multiplex(n) {
  $("run").disabled = $("more").disabled = true;
  $("count").value = n;
  $("live").hidden = false;
  $("lanes").innerHTML = "";
  $("ticker").innerHTML = "";

  tick("settings", `<b>SETTINGS</b> exchanged · one connection, ${n} streams to come`);

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

  // Fire them all, and draw each as it individually resolves rather than waiting
  // for the whole batch — that is what makes the strip fill in live.
  let done = 0;
  const clock = setInterval(() => {
    $("viz-clock").textContent = `${(performance.now() - t0).toFixed(0)} ms`;
  }, 30);

  await Promise.all(
    urls.map((u, i) =>
      fetch(u, { cache: "no-store" }).then(async (r) => {
        await r.arrayBuffer();
        done++;
        // the request's own timing entry, if the browser has filed it yet
        const entry = performance.getEntriesByName(new URL(u, location).href)[0];
        _batchSpan = Math.max(_batchSpan, performance.now() - t0);
        placeBar(i, n, entry, t0);
        const streamId = 2 * i + 1; // client streams are odd (§5.1.1)
        if (i < 6 || i % 8 === 0)
          tick("data", `stream <b>${streamId}</b> · HEADERS + DATA · ${r.status} · ${done}/${n} done`);
      })
    )
  );

  clearInterval(clock);
  const wall = performance.now() - t0;
  $("viz-clock").textContent = `${wall.toFixed(0)} ms`;
  tick("settings", `<b>done</b> · ${n} responses on ${countOpened(before)} new connection(s)`);

  summarise(n, before, wall);
  $("run").disabled = $("more").disabled = false;
  _batchSpan = 100;
}

function countOpened(before) {
  const entries = performance.getEntriesByType("resource").slice(before);
  return entries.filter(fresh).length;
}

function summarise(n, before, wall) {
  const entries = performance.getEntriesByType("resource").slice(before);
  const protocols = new Set(entries.map((e) => e.nextHopProtocol).filter(Boolean));
  const opened = entries.filter(fresh).length;
  const slowest = entries.reduce((m, e) => Math.max(m, e.duration), 0);

  $("result").hidden = false;
  $("r-total").textContent = n;
  $("r-proto").innerHTML = [...protocols].map(protoTag).join(" ") || "—";
  $("r-conns").textContent = opened === 0 ? "0 — every one reused this page's" : opened;
  $("r-wall").textContent = `${wall.toFixed(0)} ms`;
  $("r-max").textContent = `${slowest.toFixed(1)} ms`;
  $("r-note").textContent =
    opened === 0
      ? `${n} requests interleaved on one TCP connection and one TLS handshake. Over HTTP/1.1 the same page would have needed ${Math.ceil(n / 6)} rounds on six connections.`
      : `${opened} of ${n} opened a connection of their own, which is what a browser does when a connection is at its stream limit.`;
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
  showHero();
  showOwnResources();
  showRefusals();

  // ?run=N runs the multiplexing demonstration on load, so the result can be
  // linked to directly instead of described. Anything unparseable is ignored
  // rather than clamped to a default, so a typo shows nothing instead of
  // quietly showing the wrong number.
  const n = Number(new URLSearchParams(location.search).get("run"));
  if (Number.isInteger(n) && n > 0 && n <= 1024) multiplex(n);
});
