// Runs the UI's own toggle script against a stub DOM and prints the POST body
// it produces. Script comes on stdin, JSON so quoting never matters:
//   { "script": "<js>", "state": "on"|"off" }
// Exists because a toggle that posts its current state instead of the opposite
// is invisible to any test that only looks for a button.
let raw = "";
process.stdin.on("data", (c) => (raw += c));
process.stdin.on("end", () => {
  const { script, state } = JSON.parse(raw);
  const els = {};
  const el = (id) => (els[id] = els[id] || { id, textContent: "", innerHTML: "", className: "", disabled: false });
  const posts = [];
  global.document = {
    querySelector: () => ({ content: "token" }),
    getElementById: el,
    addEventListener: () => {},
    hidden: false,
  };
  global.setInterval = () => 0;
  global.clearInterval = () => {};
  global.fetch = (url, opts) => {
    if (url === "/api/status") {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ tether: state, rows: [], dry_run: false }) });
    }
    if (url === "/api/log") {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ events: [] }) });
    }
    if (url === "/api/tether") {
      posts.push(JSON.parse(opts.body));
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ ok: true, argv: [] }) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  };
  eval(script);
  setTimeout(() => {
    els["toggle"].onclick();
    setTimeout(() => {
      process.stdout.write(JSON.stringify(posts));
      process.exit(0);
    }, 30);
  }, 30);
});
