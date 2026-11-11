"use client";
import { useState } from "react";
import { FileUp, ScanSearch, ShieldAlert, ShieldCheck, ShieldQuestion, LoaderCircle } from "lucide-react";
import type { ScreeningResult } from "@/lib/types";
import { screenEvidence } from "@/lib/api";

export function ScreeningPanel() {
  const [content, setContent] = useState("");
  const [context, setContext] = useState("");
  const [file, setFile] = useState<File | undefined>();
  const [result, setResult] = useState<ScreeningResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!content.trim() && !file) { setError("Paste evidence or choose a PDF, TXT, LOG or JSON file."); return; }
    setBusy(true); setError(""); setResult(null);
    try { setResult(await screenEvidence({ content: content.trim() || undefined, file, context })); }
    catch (e) { setError(e instanceof Error ? e.message : "Screening failed."); }
    finally { setBusy(false); }
  }
  const verdict = (result?.verdict || "").toUpperCase();
  const VerdictIcon = verdict === "MALICIOUS" ? ShieldAlert : verdict === "BENIGN" ? ShieldCheck : ShieldQuestion;

  return <section className="panel screening-panel">
    <div className="panel-heading"><div><div className="eyebrow">EVIDENCE TRIAGE</div><h2>Security screening</h2><p>Submit logs, commands, IOC text or an evidence file for analysis.</p></div><div className="heading-icon"><ScanSearch size={22}/></div></div>
    <div className="screen-grid">
      <div className="screen-inputs">
        <label className="field-label">Evidence / security log</label>
        <textarea className="evidence-area" value={content} onChange={e => setContent(e.target.value)} placeholder={"Paste suspicious command, log entry, IP, URL or hash...\n\nExample: powershell.exe -EncodedCommand ..."} />
        <div className="field-label">Or upload a file <span className="muted">(PDF, TXT, LOG, JSON · max 15 MB)</span></div>
        <label className="upload-box"><FileUp size={21}/><span>{file ? file.name : "Choose evidence file"}</span><small>Browse from your computer</small><input type="file" accept=".pdf,.txt,.log,.json" onChange={e => setFile(e.target.files?.[0])}/></label>
        {file && <button className="text-button" onClick={() => setFile(undefined)}>Remove selected file</button>}
        <label className="field-label" htmlFor="context">Operational context <span className="muted">(optional)</span></label>
        <input id="context" className="text-input" value={context} onChange={e => setContext(e.target.value)} placeholder="e.g. Endpoint alert from workstation 04"/>
        <button className="primary-button" onClick={run} disabled={busy}>{busy ? <LoaderCircle className="spin" size={17}/> : <ScanSearch size={17}/>} {busy ? "Analyzing evidence..." : "Analyze evidence"}</button>
        {error && <div className="error-banner">{error}</div>}
      </div>
      <div className="result-area">
        {!result ? <div className="result-placeholder"><div className="empty-icon"><ShieldQuestion size={27}/></div><h3>Analysis results will appear here</h3><p>Screening returns a verdict, risk score, extracted indicators, MITRE ATT&CK techniques and recommended action.</p></div> :
          <div className="result-content">
            <div className={`verdict-card ${verdict.toLowerCase()}`}><VerdictIcon size={24}/><div><small>SCREENING VERDICT</small><h3>{verdict || "INCONCLUSIVE"}</h3></div><div className="risk"><b>{result.risk_score ?? "—"}</b><small>RISK / 100</small></div></div>
            <div className="metric-row"><div><small>CONFIDENCE</small><b>{result.confidence == null ? "—" : `${Math.round(result.confidence * 100)}%`}</b></div><div><small>RECOMMENDED ACTION</small><b>{result.recommended_action || "—"}</b></div></div>
            <h4>Summary</h4><p className="result-summary">{result.summary || "No summary returned."}</p>
            <h4>Findings</h4>{result.findings?.length ? <ul className="result-list">{result.findings.map((f,i)=><li key={i}>{f}</li>)}</ul> : <p className="muted">No findings returned.</p>}
            <h4>Extracted indicators</h4><div className="ioc-grid">{Object.entries(result.iocs || {}).map(([k,v])=><div key={k}><small>{k.toUpperCase()}</small><b>{v.length}</b>{v.length > 0 && <p>{v.join(", ")}</p>}</div>)}</div>
            <h4>MITRE ATT&CK techniques</h4><div className="chips">{result.mitre_techniques?.length ? result.mitre_techniques.map(t=><span key={t}>{t}</span>) : <span className="muted">None identified</span>}</div>
            {!!result.sources?.length && <><h4>Retrieved sources</h4><ul className="result-list">{result.sources.map(s=><li key={s.citation}>{s.citation}: {s.title} ({s.source}) {s.url && <a href={s.url} target="_blank" rel="noreferrer">Open ↗</a>}</li>)}</ul></>}
            <p className="disclaimer">Automated triage is decision support, not proof of compromise. Validate findings before taking action.</p>
          </div>}
      </div>
    </div>
  </section>;
}