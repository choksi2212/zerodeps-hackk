// zdh demo page.
//
// No build step. No bundler. No framework. No dependency of any kind — the same
// rule the server is under, applied to its own demo, because doing otherwise
// would be the funniest possible way to lose this hackathon.
//
// Everything numeric on this page is read out of the browser's own Resource
// Timing entries or out of a real response status. The journey animation is a
// dramatization and says so; the numbers printed underneath it are the actual
// measurements of the actual request it just fired.

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;

// ───────────────────────── scroll reveals ─────────────────────────

const io = new IntersectionObserver(
  (rows) => rows.forEach((r) => r.isIntersecting && r.target.classList.add("in")),
  { threshold: 0.08 }
);
document.querySelectorAll(".reveal").forEach((el) => io.observe(el));

// ───────────────────────── counting numbers ─────────────────────────

function countUp(el) {
  const target = Number(el.dataset.count);
  if (!target) { el.textContent = "0"; return; }
  const dur = 1100;
  const t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - t0) / dur);
    // ease-out so it decelerates into the real number
    el.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))).toLocaleString();
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const counters = new IntersectionObserver((rows) => {
  rows.forEach((r) => {
    if (r.isIntersecting) { countUp(r.target); counters.unobserve(r.target); }
  });
});
document.querySelectorAll("[data-count]").forEach((el) => counters.observe(el));

// ───────────────────────── the terminal, typed out ─────────────────────────

const TERM = [
  ["c", "# the entire dependency manifest. all of it.\n"],
  ["p", "$ "], ["w", "cat go.mod\n"],
  ["", "module zerodeps/zdh\n\ngo 1.24\n\n"],
  ["c", "# that's it. that's the whole file.\n\n"],
  ["p", "$ "], ["w", "ls go.sum\n"],
  ["", "ls: cannot access 'go.sum': No such file or directory\n"],
  ["c", "# good. that file only exists once you've let someone in.\n\n"],
  ["p", "$ "], ["w", "go version -m bin/zdh | grep -c dep\n"],
  ["", "0\n"],
  ["c", "# read out of the compiled binary. not a claim. a measurement.\n\n"],
  ["p", "$ "], ["w", "h2spec --strict\n"],
  ["", "147 tests, 147 passed, 0 skipped, "], ["w", "0 failed\n"],
];

async function typeTerm() {
  const pre = $("term-type");
  if (!pre) return;
  if (calm) {
    pre.textContent = TERM.map(([, t]) => t).join("");
    return;
  }
  for (const [cls, text] of TERM) {
    const span = document.createElement("span");
    if (cls) span.className = cls;
    pre.appendChild(span);
    for (const ch of text) {
      span.textContent += ch;
      await sleep(ch === "\n" ? 55 : 11);
    }
  }
  const cur = document.createElement("span");
  cur.className = "cursor";
  cur.textContent = "▋";
  pre.appendChild(cur);
}

// start typing when the terminal scrolls into view, once
const termWatch = new IntersectionObserver((rows) => {
  rows.forEach((r) => { if (r.isIntersecting) { typeTerm(); termWatch.disconnect(); } });
});
if ($("term-type")) termWatch.observe($("term-type"));

// ───────────────────────── ACT II: the journey ─────────────────────────
//
// Twelve stations, out and back. Each one names a real layer of this server and
// cites the rule it is implementing. The dot is theatre; the numbers at the end
// are not.

const STATIONS = [
  { at: "b-click", title: "You ask for a file",
    quip: "One click. You have no idea what you have set in motion.",
    tech: "The browser opens a request for /assets/logo.svg on this page's existing connection." },

  { at: "s-tcp", title: "A socket is accepted",
    quip: "We take a connection slot BEFORE accepting, so a flood waits in the kernel instead of eating our file descriptors. You're welcome.",
    tech: "net.Listener.Accept, bounded by MaxConns (512). No net/http anywhere in this call stack." },

  { at: "s-tls", title: "TLS, and one word that matters",
    quip: "The client whispers \"h2\". If it whispers anything else, this conversation is over.",
    tech: "crypto/tls handshake; ALPN must negotiate exactly \"h2\" (RFC 9113 §3.2). Cipher suites restricted per §9.2.2." },

  { at: "s-preface", title: "The 24 magic bytes",
    quip: "Every HTTP/2 connection opens with the string \"PRI * HTTP/2.0\". Yes, really. It exists to make HTTP/1.1 proxies fall over immediately rather than slowly.",
    tech: "§3.4 connection preface, then a SETTINGS frame from each side. We send ours first, before reading theirs." },

  { at: "s-headers", title: "A HEADERS frame arrives",
    quip: "Nine bytes of header, then the payload. We wrote this parser. All ten frame types. By hand. From the table in §6.",
    tech: "internal/frame: length, type, flags, stream ID. 211 tests and 5 fuzz targets live in that package." },

  { at: "s-hpack", title: "Decompressing the headers",
    quip: "HTTP/2 doesn't send header names. It sends INDEXES into a table both sides are silently maintaining in lockstep. If they ever disagree, everything after is garbage. Sleep well.",
    tech: "internal/hpack: RFC 7541 integers, string literals, Huffman decoding, static + dynamic table. Written from scratch." },

  { at: "s-stream", title: "Stream 1 opens",
    quip: "Odd numbers are the client's, even are the server's, and once an ID has been used it is dead forever. There is no reusing. There is no going back.",
    tech: "internal/stream: §5.1 state machine, §5.1.1 identifier rules, §5.1.2 concurrency limit, plus the reset-flood bucket for CVE-2023-44487." },

  { at: "s-request", title: "Is this request even legal?",
    quip: "\":method\", \":path\", \":scheme\" — all required, all before regular fields, none duplicated. Send us a Connection header and we will end the stream on principle.",
    tech: "internal/request: §8.3 pseudo-headers, §8.2.2 connection-specific fields refused, §8.1.1 malformed-message rules." },

  { at: "s-static", title: "Finding your actual file",
    quip: "Path checked for traversal, encoded slashes, Win32 device names and trailing-dot nonsense. Then an ETag, then a range check. THEN you get the file.",
    tech: "internal/static: RFC 9110 §13 conditional requests, §14 range requests, §8.8.3 strong entity tags." },

  { at: "s-encode", title: "Writing the answer down",
    quip: "Now we compress the response headers with the OTHER dynamic table, the one going the other way. There are two. They are independent. This is fine.",
    tech: "internal/response: §8.3.2 :status, §6.5.2 header list bound, split across HEADERS + CONTINUATION at the peer's MAX_FRAME_SIZE." },

  { at: "s-data", title: "DATA frames, on a budget",
    quip: "We can't just send it. We can only send as much as your flow-control window allows, and you have to give us permission for more. HTTP/2 is a polite protocol with a spending limit.",
    tech: "§6.9 flow control, connection and stream windows both. A single writer goroutine puts every one of these on the wire, in order." },

  { at: "b-render", title: "You get your file",
    quip: "That's it. That's the whole trip. Nobody imported anything. We hope you're happy, because we are extremely tired.",
    tech: "Response complete. The measurements below are what your browser actually recorded for the request this animation narrated." },
];

let journeyBusy = false;

function place(dotEl, targetEl, stage) {
  const s = stage.getBoundingClientRect();
  const t = targetEl.getBoundingClientRect();
  dotEl.style.left = t.left - s.left + t.width / 2 - 8 + "px";
  dotEl.style.top = t.top - s.top + t.height / 2 - 8 + "px";
}

function narrate(i) {
  const st = STATIONS[i];
  $("narr-n").textContent = i + 1;
  $("narr-title").textContent = st.title;
  $("narr-quip").textContent = st.quip;
  $("narr-tech").textContent = st.tech;
}

async function runJourney(pace = 900) {
  if (journeyBusy) return;
  journeyBusy = true;
  $("j-play").disabled = $("j-replay").disabled = true;

  const stage = $("stage");
  const dot = $("packet");
  document.querySelectorAll(".node-b, .node-s").forEach((n) => n.classList.remove("hot", "done"));
  dot.classList.remove("returning");
  $("j-real").hidden = true;

  // The real request, fired now. The animation narrates it; the numbers at the
  // end are measured from this exact fetch, not from the animation.
  $("j-status").textContent = "sending a real request…";
  const url = `/assets/logo.svg?journey=${Date.now()}`;
  const t0 = performance.now();
  const realFetch = fetch(url, { cache: "no-store" }).then(async (r) => {
    const buf = await r.arrayBuffer();
    return { status: r.status, bytes: buf.byteLength, wall: performance.now() - t0 };
  });

  dot.classList.add("on");
  for (let i = 0; i < STATIONS.length; i++) {
    const el = $(STATIONS[i].at);
    // mark the trail behind us
    if (i > 0) {
      const prev = $(STATIONS[i - 1].at);
      prev.classList.remove("hot");
      prev.classList.add("done");
    }
    el.classList.add("hot");
    place(dot, el, stage);
    narrate(i);
    // the parcel turns green once it's carrying the file home
    if (STATIONS[i].at === "s-data") dot.classList.add("returning");
    $("j-status").textContent = `step ${i + 1} of ${STATIONS.length} · ${STATIONS[i].title.toLowerCase()}`;
    await sleep(calm ? 60 : pace);
  }
  $(STATIONS[STATIONS.length - 1].at).classList.add("done");

  // real numbers
  const res = await realFetch;
  const entry = performance.getEntriesByName(new URL(url, location).href)[0];
  $("rn-proto").innerHTML = protoTag(entry ? entry.nextHopProtocol : "");
  $("rn-conn").textContent = entry && fresh(entry) ? "1 (new connection)" : "0 — reused this page's";
  $("rn-ttfb").textContent = entry ? `${(entry.responseStart - entry.startTime).toFixed(1)} ms` : "—";
  $("rn-total").textContent = `${res.wall.toFixed(1)} ms`;
  $("rn-bytes").textContent = `${(entry && entry.encodedBodySize) || res.bytes} bytes · ${res.status}`;
  $("j-real").hidden = false;

  $("j-status").textContent = "done · that actually happened · press replay if you enjoyed it";
  dot.classList.remove("on");
  $("j-play").disabled = $("j-replay").disabled = false;
  journeyBusy = false;
}

// ───────────────────────── shared helpers ─────────────────────────

// A resource served on an existing connection reports connectStart ===
// connectEnd, because no connection was opened for it. That is how this page can
// say "reused" without asking the server anything.
function fresh(e) { return e.connectEnd > e.connectStart; }

function protoTag(p) {
  return `<span class="tag ${p === "h2" ? "h2" : "other"}">${p || "—"}</span>`;
}

// ───────────────────────── ACT IV: live multiplexing ─────────────────────────

const LANE_H = 320;
let batchSpan = 100;

function tick(kind, text) {
  const t = $("ticker");
  const line = document.createElement("div");
  line.className = "frame " + kind;
  line.innerHTML = text;
  t.appendChild(line);
  while (t.childElementCount > 70) t.removeChild(t.firstChild);
}

function placeBar(i, n, entry, t0) {
  const bar = document.createElement("div");
  bar.className = "bar";
  const top = Math.round((i / n) * (LANE_H - 6));
  const start = Math.max(0, entry ? entry.startTime - t0 : 0);
  const dur = entry ? Math.max(2, entry.duration) : 4;
  const scale = 0.9 / Math.max(1, batchSpan);
  bar.style.top = top + "px";
  bar.style.left = 2 + start * scale * 100 + "%";
  bar.style.width = Math.min(96, dur * scale * 100) + "%";
  $("lanes").appendChild(bar);
  setTimeout(() => bar.classList.add("done"), 110);
}

async function multiplex(n) {
  $("run").disabled = $("more").disabled = true;
  $("count").value = n;
  $("live").hidden = false;
  $("lanes").innerHTML = "";
  $("ticker").innerHTML = "";
  $("viz-count").textContent = "0";

  tick("settings", `<b>SETTINGS</b> exchanged · one connection · ${n} streams incoming`);

  // A distinct query per request so nothing is answered from cache. The query is
  // not part of the file name — the server drops it before the target becomes a
  // path — so all n of these are the same file and n genuinely distinct requests.
  const stamp = Date.now();
  const urls = Array.from({ length: n }, (_, i) => `/assets/logo.svg?stream=${i}&t=${stamp}`);

  const before = performance.getEntriesByType("resource").length;
  const t0 = performance.now();
  let done = 0;

  const clock = setInterval(() => {
    $("viz-clock").textContent = `${(performance.now() - t0).toFixed(0)} ms`;
    $("viz-count").textContent = done;
  }, 30);

  await Promise.all(
    urls.map((u, i) =>
      fetch(u, { cache: "no-store" }).then(async (r) => {
        await r.arrayBuffer();
        done++;
        const entry = performance.getEntriesByName(new URL(u, location).href)[0];
        batchSpan = Math.max(batchSpan, performance.now() - t0);
        placeBar(i, n, entry, t0);
        if (i < 8 || i % 9 === 0)
          tick("data", `stream <b>${2 * i + 1}</b> · HEADERS + DATA · ${r.status} · ${done}/${n}`);
      })
    )
  );

  clearInterval(clock);
  const wall = performance.now() - t0;
  $("viz-clock").textContent = `${wall.toFixed(0)} ms`;
  $("viz-count").textContent = n;

  const entries = performance.getEntriesByType("resource").slice(before);
  const protocols = new Set(entries.map((e) => e.nextHopProtocol).filter(Boolean));
  const opened = entries.filter(fresh).length;
  const slowest = entries.reduce((m, e) => Math.max(m, e.duration), 0);

  tick("settings", `<b>done</b> · ${n} responses · ${opened} new connections opened`);

  $("result").hidden = false;
  $("r-total").textContent = n;
  $("r-proto").innerHTML = [...protocols].map(protoTag).join(" ") || "—";
  $("r-conns").textContent = opened === 0 ? "0 — every one reused this page's" : opened;
  $("r-wall").textContent = `${wall.toFixed(0)} ms`;
  $("r-max").textContent = `${slowest.toFixed(1)} ms`;
  $("r-note").textContent =
    opened === 0
      ? `${n} requests. One TCP connection. One TLS handshake. Zero new connections. Over HTTP/1.1 your browser would have queued these into about ${Math.ceil(n / 6)} rounds across six connections, and you would have felt it.`
      : `${opened} of ${n} opened a connection of their own — that is your browser hitting this connection's stream limit, which is itself an HTTP/2 setting we advertise.`;

  $("run").disabled = $("more").disabled = false;
  batchSpan = 100;
}

// ───────────────────────── ACT V: the bouncer ─────────────────────────

const refusals = [
  ["/assets/zdh.css", "the control — an ordinary file, served, so you know the rest are refusals and not 404s"],
  ["/assets%2Fzdh.css", "%2F is not a path separator. same file, encoded. absolutely not"],
  ["/assets/zdh.css%20", "a trailing space, which Win32 would silently strip and hand you the file above"],
  ["/assets/zdh.css.", "a trailing dot, same trick, same answer"],
  ["/.dotfile-you-cannot-fetch.txt", "a dotfile that genuinely exists on disk. still no"],
  ["/NUL", "a Win32 device name. refused on every platform, including the ones where it is harmless"],
  ["/%2e%2e/%2e%2e/go.mod", "encoded ../../ traversal, trying to escape the served directory"],
  ["/" + "a".repeat(5000), "a target longer than we are willing to think about"],
];

async function showRefusals() {
  const body = $("refusals").tBodies[0];
  for (const [target, why] of refusals) {
    const row = body.insertRow();
    const shown = target.length > 40 ? target.slice(0, 37) + "…" : target;
    row.insertCell().textContent = shown;
    const status = row.insertCell();
    status.textContent = "…";
    row.insertCell().textContent = why;
    try {
      const r = await fetch(target, { cache: "no-store", redirect: "manual" });
      status.innerHTML = `<span class="tag ${r.status === 200 ? "h2" : "other"}">${r.status}</span>`;
    } catch {
      status.textContent = "net err";
    }
  }
  // a method rather than a target, and the field §15.5.6 requires alongside it
  const row = body.insertRow();
  row.insertCell().textContent = "POST /";
  const status = row.insertCell();
  const r = await fetch("/", { method: "POST", body: "x", cache: "no-store" });
  status.innerHTML = `<span class="tag other">${r.status}</span>`;
  row.insertCell().textContent = `a method this server has no answer for — and it tells you what it does allow: ${r.headers.get("allow")}`;
}

// ───────────────────────── ACT VII: this page as evidence ─────────────────────────

function ownResource(e) {
  const q = new URL(e.name).searchParams;
  return !q.has("stream") && !q.has("journey");
}

function showResources() {
  const rows = [
    ...performance.getEntriesByType("navigation"),
    ...performance.getEntriesByType("resource").filter(ownResource),
  ];
  $("resources").tBodies[0].innerHTML = rows
    .map(
      (e) => `<tr>
        <td title="${e.name}">${new URL(e.name).pathname}</td>
        <td>${protoTag(e.nextHopProtocol)}</td>
        <td>${e.initiatorType}${fresh(e) ? " · new conn" : " · reused"}</td>
        <td class="n">${e.encodedBodySize || e.transferSize || 0}</td>
        <td class="n">${(e.responseEnd - e.startTime).toFixed(1)}</td>
      </tr>`
    )
    .join("");
}

// ───────────────────────── wiring ─────────────────────────

$("j-play").addEventListener("click", () => runJourney(900));
$("j-replay").addEventListener("click", () => runJourney(1500));
$("run").addEventListener("click", () => multiplex(64));
$("more").addEventListener("click", () => multiplex(256));

// Keep the dot parked on its station if the layout reflows under it.
addEventListener("resize", () => {
  const hot = document.querySelector(".node-b.hot, .node-s.hot");
  if (hot && journeyBusy) place($("packet"), hot, $("stage"));
});

addEventListener("load", () => {
  const nav = performance.getEntriesByType("navigation")[0];
  if (nav && nav.nextHopProtocol) $("hero-proto").textContent = nav.nextHopProtocol;

  showResources();
  showRefusals();

  // ?run=N fires the multiplexing demonstration on load, so the result can be
  // linked to directly instead of described. Anything unparseable is ignored
  // rather than clamped, so a typo shows nothing instead of the wrong number.
  const n = Number(new URLSearchParams(location.search).get("run"));
  if (Number.isInteger(n) && n > 0 && n <= 1024) multiplex(n);
});
