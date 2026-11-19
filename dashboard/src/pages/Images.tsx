import { useData } from "../context";
import { num } from "../format";
import { SevCounts, showPath } from "./Infrastructure";

export function Images() {
  const { data } = useData();
  const images = data.images ?? [];
  return (
    <div>
      <h1>Container images</h1>
      {images.length === 0 ? (
        <div class="card"><div class="empty">No container image was scanned. Save one with <span class="mono">docker save -o app.tar IMAGE</span> and add <span class="mono">--image app.tar</span> to the scan (offline, no registry needed).</div></div>
      ) : images.map((im) => (
        <section key={im.image} class="card" style={{ marginBottom: "14px" }} aria-labelledby={`img-${im.image}`}>
          <h2 id={`img-${im.image}`} style={{ marginTop: 0 }}><span class="mono">{im.image}</span> <SevCounts counts={im.by_severity} /></h2>
          <div class="grid cols-3">
            {([[im.vulnerabilities, `vulnerabilities in ${num(im.vulnerable_packages)} package${im.vulnerable_packages === 1 ? "" : "s"}`],
              [im.fixable, "of them have a fixed version"], [im.kev, "known exploited (CISA KEV)"],
              [im.misconfigurations, "misconfigurations"], [im.secrets, "possible secrets"]] as [number, string][]).map(([v, l]) => (
              <div class="kpi" key={l}><span class="v">{num(v)}</span><span class="l">{l}</span></div>
            ))}
          </div>
          {im.locations.length > 0 && <p class="muted">Scanned inside the image: {im.locations.join(" · ")}</p>}
          <p><a href="#/findings" onClick={(e) => { e.preventDefault(); showPath(`image:${im.image}`); }}>Show all {num(im.findings)} findings</a></p>
          {im.vulnerabilities > 0 && im.fixable * 2 < im.vulnerabilities && <p class="muted">Most vulnerabilities without a fixed version come from the base image: rebuilding on a newer base usually removes more of them than upgrading packages one by one.</p>}
        </section>
      ))}
    </div>
  );
}
