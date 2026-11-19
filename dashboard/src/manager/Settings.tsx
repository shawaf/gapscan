import { useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { Models, ScannerAvail, Settings } from "./api";
import { Err, PageHead, Segmented } from "./common";
import { Icon } from "./icons";
import { Memories } from "./Memories";
import { useLoad } from "./useApi";
import { WorkspaceCard } from "./Workspace";

export function SettingsPage({ project }: { project: { id: number; name: string } | null }) {
  const models = useLoad(() => api<Models>("GET", "/api/models"), []);
  const settings = useLoad(() => api<Settings>("GET", "/api/settings"), []);
  const scanners = useLoad(() => api<ScannerAvail[]>("GET", "/api/scanners"), []);
  const [msg, setMsg] = useState("");
  const save = async (patch: Partial<Settings>) => {
    try { await api("PUT", "/api/settings", patch); settings.reload(); models.reload(); scanners.reload(); setMsg(""); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
  };
  const chosen = new Set(settings.data?.scanners ?? []);
  const toggle = (name: string) => {
    const next = new Set(chosen);
    if (next.has(name)) next.delete(name); else next.add(name);
    if (next.size === 0) { setMsg("Keep at least one scanner enabled."); return; }
    void save({ scanners: [...next] });
  };
  return (
    <>
      <PageHead title="Settings" sub="Scanners, the review model and the defaults for every run. Each run can override them on the Runs page." />
      <Err text={msg || models.error || settings.error || scanners.error} />
      <div class="cc-grid g2">
        <section class="cc-card">
          <h2 class="big">Scanners</h2>
          <p class="cc-note" style="margin-top:-6px">Which tools run by default. A tool that is not installed is skipped and the run says so.</p>
          <div class="cc-scanners">
            {scanners.data?.map((s) => (
              <label key={s.name}>
                <input type="checkbox" checked={chosen.has(s.name)} onChange={() => toggle(s.name)} />
                <span><span class="nm">{s.name}</span><span class="ds">{s.description}</span></span>
                {s.available ? <span class="av"><Icon name="check" size={12} />Available{s.version ? ` · ${s.version}` : ""}</span> : <span class="av no"><Icon name="x" size={12} />Unavailable</span>}
              </label>
            ))}
            {!scanners.data && <label><span class="cc-note">Checking scanners...</span></label>}
          </div>
        </section>
        <section class="cc-card">
          <h2 class="big">Review model</h2>
          <p class="cc-note" style="margin-top:-6px">Endpoint <span class="mono">{models.data?.endpoint}</span>. It must stay on this machine or your internal network.</p>
          {models.data?.error && <div class="fd-banner bad"><b><Icon name="x" size={12} /> The local model server is not answering</b><p>AI review is off until it is back. Scans still run with scanners only. {models.data.error}</p></div>}
          {models.data?.profiles.map((p) => (
            <label key={p.name} style="display:flex;gap:10px;align-items:flex-start;padding:10px 0;border-top:1px solid var(--line);cursor:pointer">
              <input type="radio" name="profile" checked={p.selected} onChange={() => save({ profile: p.name })} style="margin-top:3px;accent-color:var(--accent)" />
              <span style="flex:1"><b>{p.name[0]?.toUpperCase() + p.name.slice(1)}</b> <span class="mono">{p.model}</span> {p.installed ? <span class="badge2 ok"><Icon name="check" size={12} />Installed</span> : <span class="badge2">Not installed</span>}
                <span class="cc-note" style="display:block">{p.note}</span></span>
            </label>
          ))}
        </section>
        <section class="cc-card">
          <h2 class="big">Review defaults</h2>
          {settings.data && (
            <>
              <label class="cc-field"><span>Findings to review per run</span><input class="cc-input mono" type="number" min={0} max={100000} value={settings.data.triage_limit} onChange={(e) => save({ triage_limit: Number(e.currentTarget.value) })} />
                <span class="cc-note">The highest-severity findings are reviewed first; the rest stay unreviewed. Set 0 to review every finding (about 6 to 10 seconds each on a 30B model).</span></label>
              <label class="cc-field"><span>Tool calls per finding</span><input class="cc-input mono" type="number" min={0} max={10} value={settings.data.max_tool_calls} onChange={(e) => save({ max_tool_calls: Number(e.currentTarget.value) })} />
                <span class="cc-note">How many times the reviewer may look up code before it must answer. 0 answers from the code shown; more is slower.</span></label>
              <div class="cc-field"><span class="lbl">Default run type</span>
                <Segmented block label="Default run type" value={settings.data.default_preset} onChange={(v) => save({ default_preset: v })} options={[{ id: "full", label: "Full scan with AI review" }, { id: "scanners", label: "Scanners only" }]} /></div>
              <div class="cc-field"><span class="lbl">ASVS level</span>
                <Segmented block label="ASVS level" value={String(settings.data.asvs_level)} onChange={(v) => save({ asvs_level: Number(v) })} options={[{ id: "1", label: "L1" }, { id: "2", label: "L2" }, { id: "3", label: "L3" }]} /></div>
              <div class="cc-switchrow"><button class="cc-toggle" role="switch" aria-checked={settings.data.deep_dive} aria-label="Deep dive into confirmed issues" onClick={() => save({ deep_dive: !settings.data?.deep_dive })} />
                <span><b style="font-size:13px">Deep dive into confirmed issues</b><span class="cc-note" style="display:block">After the AI review, investigate the top confirmed issues in depth. Only cited lines the reviewer was actually shown are kept.</span></span></div>
              <label class="cc-field"><span>Issues to deep dive per run</span><input class="cc-input mono" type="number" min={0} max={100} value={settings.data.deep_dive_limit} onChange={(e) => save({ deep_dive_limit: Number(e.currentTarget.value) })} />
                <span class="cc-note">Highest priority first; findings that are the same issue share one investigation. 0 turns it off.</span></label>
              <div class="cc-switchrow"><button class="cc-toggle" role="switch" aria-checked={settings.data.use_tools} aria-label="Let the reviewer look up code" onClick={() => save({ use_tools: !settings.data?.use_tools })} />
                <span><b style="font-size:13px">Let the reviewer look up code</b><span class="cc-note" style="display:block">Read-only tools: show code, find callers and imports, search the knowledge base. Confined to the project folder.</span></span></div>
            </>
          )}
        </section>
        <WorkspaceCard />
        <section class="cc-card">
          <h2 class="big">Ignore rules</h2>
          <p class="cc-note" style="margin-top:-6px">Drop findings you do not want to see, such as vendored code or build output, or a rule you have decided to live with.</p>
          <p style="font-size:13px">Put a <span class="mono">.gapscanignore</span> file in the project folder, one path pattern or <span class="mono">rule:&lt;id&gt;</span> per line, like a <span class="mono">.gitignore</span>:</p>
          <pre class="logbox">{"vendor/\nbuild/\n**/*.min.js\nrule:python.lang.security.audit.dangerous-system-call"}</pre>
          <p class="cc-note">Findings in matching paths, and findings of the listed rules, are left out of the results; the scanners still run. GapScan reads this file and never writes into your project, so create it yourself.</p>
        </section>
      </div>
      {project && <Memories projectId={String(project.id)} projectName={project.name} />}
    </>
  );
}
