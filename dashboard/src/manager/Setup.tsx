import { useState } from "preact/hooks";
import { api } from "./api";
import type { DataInfo, SetupStatus, Tier } from "./api";
import { useSetupQueue } from "./setupQueue";
import type { Item } from "./setupQueue";
import { Err, PageHead, Skeleton, StatusBadge } from "./common";
import { Icon, Spinner } from "./icons";
import { navigate } from "../store";
import { useLoad } from "./useApi";

const gb = (bytes: number): string => `${(bytes / 1e9).toFixed(bytes < 1e9 ? 2 : 1)} GB`;
const mb = (bytes: number): string => (bytes < 1e9 ? `${Math.round(bytes / 1e6)} MB` : gb(bytes));

function Done() { return <span class="badge2 ok"><Icon name="check" size={12} />Ready</span>; }
function Todo({ text }: { text: string }) { return <span class="badge2 warn">{text}</span>; }

export function SetupPage() {
  const st = useLoad(() => api<SetupStatus>("GET", "/api/setup"), []);
  const info = useLoad(() => api<DataInfo>("GET", "/api/data"), []);
  const [pick, setPick] = useState<string | null>(null);
  const q = useSetupQueue(() => { st.reload(); info.reload(); }, st.data?.task);
  const { begin, running, task, label, msg, cancel } = q;

  const d = st.data;
  const chosen: Tier | undefined = d ? d.tiers.find((t) => t.id === (pick ?? d.selected ?? d.recommended)) : undefined;
  const hasData = (info.data?.freshness.length ?? 0) > 0 || !!info.data?.bundle;
  const ready = !!d && d.runtime.installed && d.embedding.installed && d.tiers.some((t) => t.installed);
  const pct = task?.progress && task.progress.total ? Math.round((100 * task.progress.done) / task.progress.total) : 0;
  const modelItems = (t: Tier): Item[] => [
    ...(t.installed ? [] : [{ step: "model", pack: t.id, label: t.ollama ? `Linking ${t.alias} from Ollama` : `Downloading ${t.alias}` }]),
    ...(d?.embedding.installed ? [] : [{ step: "embedding", label: "Downloading the knowledge-base model" }]),
  ];

  return (
    <>
      <PageHead title="Setup" sub="Get this machine ready. Downloads happen once, here. Scans never go online." />
      <Err text={st.error || msg} />
      {!d ? <Skeleton rows={6} /> : (
        <>
          <div class="fd-banner grey" style="margin:0 0 16px" role="note">
            <b><Icon name="lock" size={13} /> The only time GapScan goes online</b>
            <p>Setup connects to {d.hosts.join(", ")} and nowhere else. Every file is checked against a checksum pinned in this app (list dated {d.manifest_created}) and discarded if it does not match. After setup, everything runs on this machine.</p>
          </div>

          <section class="cc-card" style="margin-bottom:16px" aria-labelledby="s1">
            <div class="cc-row"><h2 id="s1" style="margin:0">1. This machine</h2><span class="grow" /><Done /></div>
            <div class="kv" style="margin:10px 0">
              <span>System <b>{d.hardware.os} {d.hardware.arch}</b></span>
              <span>Memory <b>{d.hardware.ram_gb} GB</b></span>
              <span>Usable by the AI <b>{d.hardware.usable_gb} GB</b></span>
              <span>Free disk <b>{Math.round(d.hardware.disk_free_gb)} GB</b></span>
              <span>Graphics <b>{d.hardware.gpu === "metal" ? "Apple silicon (Metal)" : d.hardware.gpu === "nvidia" ? `${d.hardware.gpu_name} ${d.hardware.vram_gb} GB` : "none, the processor is used"}</b></span>
            </div>
            <p class="cc-note" style="margin:0">{d.recommended ? <>Recommended for this machine: <b>{d.tiers.find((t) => t.id === d.recommended)?.alias}</b>.</> : "This machine has less memory than the smallest model needs. GapScan still runs every scanner; only the AI review stays off."}</p>
          </section>

          <section class="cc-card" style="margin-bottom:16px" aria-labelledby="s2">
            <div class="cc-row"><h2 id="s2" style="margin:0">2. AI engine</h2><span class="grow" />{d.runtime.installed ? <Done /> : <Todo text="Not installed" />}</div>
            <p class="cc-note" style="margin:6px 0 10px">The program that runs the model on this machine (llama.cpp {d.runtime.pack?.version ?? ""}). {d.runtime.pack ? `${mb(d.runtime.pack.size)} for ${d.platform}.` : `No build exists for ${d.platform}.`} It listens on this machine only.</p>
            <button class="btn primary" disabled={running || d.runtime.installed || !d.runtime.pack} onClick={() => begin([{ step: "engine", label: "Installing the AI engine" }])}>Install AI engine</button>
          </section>

          <section class="cc-card" style="margin-bottom:16px" aria-labelledby="s3">
            <div class="cc-row"><h2 id="s3" style="margin:0">3. AI model</h2><span class="grow" />{d.tiers.some((t) => t.installed) && d.embedding.installed ? <Done /> : <Todo text="Choose a model" />}</div>
            <div class="tbl-wrap" style="margin:10px 0"><table class="tbl"><thead><tr><th></th><th>Model</th><th class="num">Download</th><th class="num">Memory</th><th>Status</th></tr></thead><tbody>
              {d.tiers.map((t) => (
                <tr key={t.id} style={chosen?.id === t.id ? "background:var(--accent-weak)" : ""}>
                  <td><input type="radio" name="tier" aria-label={`Use ${t.alias}`} checked={chosen?.id === t.id} disabled={running || !t.fits} onChange={() => setPick(t.id)} style="accent-color:var(--accent)" /></td>
                  <td><b class="mono">{t.alias}</b><span class="sub">{t.note}</span></td>
                  <td class="num">{t.ollama || t.linked ? "0 GB" : gb(t.size)}</td><td class="num">{t.needs_gb} GB</td>
                  <td>{t.installed ? <><Done />{t.linked && <span class="sub">Using Ollama's copy</span>}</> : t.ollama && t.fits ? <span class="badge2 ok"><Icon name="check" size={12} />Found in Ollama, no download</span> : t.fits ? <span class="cc-note">Fits this machine</span> : <span class="badge2 bad"><Icon name="x" size={12} />Needs more memory</span>}</td>
                </tr>
              ))}
            </tbody></table></div>
            <p class="cc-note" style="margin:0 0 10px">A small embedding model ({d.embedding.pack ? mb(d.embedding.pack.size) : "-"}) is downloaded with it to build the knowledge base. If Ollama already has the model, it is reused and nothing is downloaded. Models are not benchmarked equally: only the first has measured results.</p>
            <button class="btn primary" disabled={running || !chosen || !chosen.fits || modelItems(chosen).length === 0} onClick={() => chosen && begin(modelItems(chosen))}>{chosen ? (chosen.installed ? "Model ready" : chosen.ollama ? `Use ${chosen.alias} from Ollama` : `Download ${chosen.alias}`) : "No model fits"}</button>
          </section>

          <section class="cc-card" style="margin-bottom:16px" aria-labelledby="s4">
            <div class="cc-row"><h2 id="s4" style="margin:0">4. Scanners</h2><span class="grow" />{d.scanner_plan.missing.length === 0 ? <Done /> : <Todo text={`${d.scanner_plan.missing.length} missing`} />}</div>
            <div class="tbl-wrap" style="margin:10px 0"><table class="tbl"><thead><tr><th>Scanner</th><th>Where it comes from</th></tr></thead><tbody>
              {d.scanners.map((x) => (
                <tr key={x.name}><td><b class="mono">{x.name}</b></td>
                  <td>{x.via === "bundled" ? <><Done /><span class="sub">Included in this app</span></> : x.via === "managed" ? <><Done /><span class="sub">Installed by GapScan</span></> : x.via === "path" ? <><Done /><span class="sub">Already on this machine ({x.path})</span></> : d.scanner_plan.unavailable.includes(x.name) ? <span class="badge2 bad"><Icon name="x" size={12} />No download offered for this system</span> : <Todo text="Will be downloaded" />}</td></tr>
              ))}
            </tbody></table></div>
            <p class="cc-note" style="margin:0 0 10px">{d.scanner_plan.size > 0 ? `${mb(d.scanner_plan.size)} to download${d.scanner_plan.python ? ", including a private copy of Python for Semgrep, Checkov and Bandit" : ""}. ` : ""}Programs GapScan installs stay in its own folder and are used instead of any other copy, so every machine runs the same versions. A scanner you already have is left alone.</p>
            <button class="btn primary" disabled={running || d.scanner_plan.size === 0} onClick={() => begin([{ step: "scanners", label: "Installing scanners" }])}>{d.scanner_plan.size === 0 ? (d.scanner_plan.missing.length ? "Nothing to download" : "Scanners ready") : `Install scanners (${mb(d.scanner_plan.size)})`}</button>
          </section>

          <section class="cc-card" style="margin-bottom:16px" aria-labelledby="s5">
            <div class="cc-row"><h2 id="s5" style="margin:0">5. Security data</h2><span class="grow" />{hasData ? <Done /> : <Todo text="Not downloaded" />}</div>
            <p class="cc-note" style="margin:6px 0 10px">Vulnerability databases, advisories and the OWASP knowledge base. {hasData ? "Already present; downloading again refreshes them." : "Needed for dependency checks and AI explanations."} On a machine without internet, import a bundle in System Health instead.</p>
            <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" disabled={running} onClick={() => begin([{ step: "data", label: "Downloading security data" }])}>{hasData ? "Refresh data" : "Download data"}</button><button class="btn" onClick={() => navigate("health")}>Import a bundle instead</button></div>
          </section>

          <section class="cc-card" style="margin-bottom:16px" aria-labelledby="s6">
            <div class="cc-row"><h2 id="s6" style="margin:0">6. Start and check</h2><span class="grow" />{d.running ? <Done /> : <Todo text="Stopped" />}</div>
            <p class="cc-note" style="margin:6px 0 10px">{d.running ? `The AI engine is running ${d.tiers.find((t) => t.id === d.active)?.alias ?? ""}.` : "It starts by itself when a scan needs it; start it here to check that the model loads."}</p>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              {d.running ? <button class="btn" disabled={running} onClick={() => begin([{ step: "stop", label: "Stopping the AI engine" }])}>Stop AI engine</button>
                : <button class="btn primary" disabled={running || !ready} onClick={() => begin([{ step: "start", pack: chosen?.id, label: "Starting the AI engine" }])}>Start AI engine</button>}
              <button class="btn" onClick={() => navigate("health")}>Open System Health</button>
            </div>
          </section>

          {task && (
            <section class="cc-card" aria-live="polite" aria-labelledby="prog">
              <div class="cc-row"><h2 id="prog" style="margin:0">{label}</h2><span class="grow" /><StatusBadge s={task.status === "running" ? "running" : task.status === "done" ? "done" : task.status === "cancelled" ? "cancelled" : "failed"} />
                {running && <button class="btn sm" onClick={cancel}>Cancel</button>}</div>
              {task.status === "running" && task.progress && task.progress.total > 0 && (
                <div style="margin:10px 0"><div class="bar2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><i style={`width:${pct}%`} /></div>
                  <span class="cc-note">{pct}% · {mb(task.progress.done)} of {mb(task.progress.total)}. Stopping keeps what is downloaded, and the next start continues from there.</span></div>
              )}
              {task.status === "running" && !task.progress?.total && <p class="cc-note"><Spinner size={12} /> Working ...</p>}
              <pre class="logbox">{task.log.join("\n")}</pre>
            </section>
          )}
        </>
      )}
    </>
  );
}
