// JobPilot MCP server (stdio, JSON-RPC 2.0, one message per line, no dependencies).
// Uses JobPilot's own backend API on http://127.0.0.1:3100 and starts it hidden if needed.
const path = require("path"), fs = require("fs"), { spawn } = require("child_process");
const API = "http://127.0.0.1:3100";
const EXE = path.join(__dirname, "backend", "target", "release", process.platform === "win32" ? "jobpilot.exe" : "jobpilot");

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function up() { try { return (await fetch(API + "/api/health", { signal: AbortSignal.timeout(1500) })).ok; } catch { return false; } }
async function ensureBackend() {
  if (await up()) return;
  if (!fs.existsSync(EXE)) throw new Error("The JobPilot backend is not built yet. Run start.bat in the app folder once.");
  // cwd = app folder: the backend keeps its data in ./data/db.json
  spawn(EXE, [], { cwd: __dirname, detached: true, stdio: "ignore", windowsHide: true }).unref();
  for (let i = 0; i < 40; i++) { await sleep(250); if (await up()) return; }
  throw new Error("Started the JobPilot backend but it did not answer on port 3100.");
}
async function call(method, p, body) {
  await ensureBackend();
  const r = await fetch(API + p, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let v; try { v = text ? JSON.parse(text) : { ok: true }; } catch { v = { text }; }
  if (!r.ok) throw new Error(`${r.status}: ${v.error || text || r.statusText}`);
  return v;
}

const STATUSES = ["new", "saved", "ready", "applied", "interview", "offer", "rejected"];
const id = { type: "string", description: "Job id (8 characters, from list_jobs)" };
const enc = encodeURIComponent;

const tools = {
  get_overview: {
    description: "JobPilot settings (no API key), whether a CV and cover-letter template are uploaded, and counts of jobs by status.",
    inputSchema: { type: "object", properties: {} },
    run: async () => {
      const s = await call("GET", "/api/state");
      const by = {};
      for (const j of s.jobs) by[j.status] = (by[j.status] || 0) + 1;
      return { settings: s.settings, cv: s.cv, cover_letter_template: s.cover, jobs: s.jobs.length, jobs_by_status: by };
    },
  },
  list_jobs: {
    description: "List jobs (newest first) with id, title, company, status, match score and flags. Optionally filter by status or a text search over title/company.",
    inputSchema: { type: "object", properties: { status: { type: "string", enum: STATUSES }, search: { type: "string" }, limit: { type: "number", description: "Default 50" } } },
    run: async a => {
      let jobs = (await call("GET", "/api/state")).jobs;
      if (a.status) jobs = jobs.filter(j => j.status === a.status);
      if (a.search) { const t = String(a.search).toLowerCase(); jobs = jobs.filter(j => `${j.title} ${j.company}`.toLowerCase().includes(t)); }
      return { total: jobs.length, jobs: jobs.slice(0, Number(a.limit) || 50) };
    },
  },
  get_job: {
    description: "Full details of one job: description, match analysis (skills matched/missing, suggested CV edits), warnings.",
    inputSchema: { type: "object", properties: { id }, required: ["id"] },
    run: async a => call("GET", `/api/jobs/${enc(a.id)}`),
  },
  add_job: {
    description: "Add a job from its description. Set analyze=true to also score it against the CV right away (uses the OpenRouter model set in JobPilot, which costs credits there).",
    inputSchema: {
      type: "object",
      properties: { jd: { type: "string", description: "The full job description (at least 40 characters)" }, title: { type: "string" }, company: { type: "string" }, url: { type: "string" }, analyze: { type: "boolean" } },
      required: ["jd"],
    },
    run: async a => call("POST", "/api/jobs", { jd: a.jd, title: a.title, company: a.company, url: a.url, analyze: !!a.analyze }),
  },
  update_job: {
    description: "Change a job's status, notes, title, company or URL. Setting status to applied records the application date.",
    inputSchema: {
      type: "object",
      properties: { id, status: { type: "string", enum: STATUSES }, notes: { type: "string" }, title: { type: "string" }, company: { type: "string" }, url: { type: "string" } },
      required: ["id"],
    },
    run: async a => {
      const { id: jid, ...patch } = a;
      await call("GET", `/api/jobs/${enc(jid)}`); // 404s for an unknown id (PATCH itself always says ok)
      await call("PATCH", `/api/jobs/${enc(jid)}`, patch);
      return call("GET", `/api/jobs/${enc(jid)}`).then(j => ({ id: j.id, title: j.title, company: j.company, status: j.status, notes: j.notes, url: j.url }));
    },
  },
  delete_job: {
    description: "Delete a job.",
    inputSchema: { type: "object", properties: { id }, required: ["id"] },
    run: async a => (await call("GET", `/api/jobs/${enc(a.id)}`), await call("DELETE", `/api/jobs/${enc(a.id)}`), { deleted: a.id }),
  },
  analyze_job: {
    description: "Score a job against the CV and propose CV edits (uses the OpenRouter model, costs credits there; takes up to a minute).",
    inputSchema: { type: "object", properties: { id }, required: ["id"] },
    run: async a => (await call("POST", `/api/jobs/${enc(a.id)}/analyze`), call("GET", `/api/jobs/${enc(a.id)}`)),
  },
  generate_documents: {
    description: "Create the tailored CV and cover letter for an analyzed job, applying only the suggested CV edits whose ids are in `accepted` (from get_job → analysis.suggestions). Uses the OpenRouter model.",
    inputSchema: { type: "object", properties: { id, accepted: { type: "array", items: { type: "number" } } }, required: ["id", "accepted"] },
    run: async a => (await call("POST", `/api/jobs/${enc(a.id)}/generate`, { accepted: (a.accepted || []).map(Number) }), { ok: true, cv: `${API}/doc/job/${a.id}/cv`, cover_letter: `${API}/doc/job/${a.id}/cover` }),
  },
  update_settings: {
    description: "Change JobPilot settings. (The OpenRouter API key can only be changed in the app itself.)",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string", description: "OpenRouter model id" },
        default_query: { type: "string", description: "Default job search query for autopilot" },
        daily_goal: { type: "number" },
        auto_prepare: { type: "boolean", description: "Autopilot prepares documents for good matches" },
        auto_threshold: { type: "number", description: "Minimum match score (0-100) for auto-prepare" },
      },
    },
    run: async a => {
      const { api_key, ...rest } = a; // never set the key from a chat
      await call("PUT", "/api/settings", rest);
      return (await call("GET", "/api/state")).settings;
    },
  },
  run_autopilot: {
    description: "Start job discovery for a search query (or the saved default), then score new jobs. Runs in the background; check list_jobs later.",
    inputSchema: { type: "object", properties: { query: { type: "string" } } },
    run: async a => call("POST", "/api/autopilot", { query: a.query }),
  },
  score_all: {
    description: "Score every job that has no match score yet (background).",
    inputSchema: { type: "object", properties: {} },
    run: async () => call("POST", "/api/score-all", {}),
  },
};

const send = o => process.stdout.write(JSON.stringify(o) + "\n");
require("readline").createInterface({ input: process.stdin }).on("line", async l => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  const ok = result => send({ jsonrpc: "2.0", id: m.id, result });
  if (m.method === "initialize") ok({ protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "jobpilot", version: "1.0.0" } });
  else if (m.method === "ping") ok({});
  else if (m.method === "tools/list") ok({ tools: Object.entries(tools).map(([name, t]) => ({ name, description: t.description, inputSchema: t.inputSchema })) });
  else if (m.method === "tools/call") {
    const { name, arguments: a = {} } = m.params || {};
    const t = tools[name];
    if (!t) return ok({ isError: true, content: [{ type: "text", text: `Unknown tool ${name}` }] });
    try { ok({ content: [{ type: "text", text: JSON.stringify(await t.run(a), null, 1) }] }); }
    catch (e) { ok({ isError: true, content: [{ type: "text", text: String(e.message || e) }] }); }
  } else send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
});
