"use client";
import { Shield, MessageSquareText, ScanSearch, Activity, Database, CircleHelp } from "lucide-react";

export type View = "overview" | "chat" | "screening";
export function Sidebar({ active, onChange, backendOnline }: {
  active: View; onChange: (view: View) => void; backendOnline: boolean | null;
}) {
  const items: { id: View; label: string; icon: typeof Activity }[] = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "chat", label: "Threat intelligence chat", icon: MessageSquareText },
    { id: "screening", label: "Evidence screening", icon: ScanSearch }
  ];
  return <aside className="sidebar">
    <div className="brand"><div className="brand-mark"><Shield size={21}/></div><div><b>CYBER<span>INTEL</span></b><small>RAG CONSOLE</small></div></div>
    <div className="nav-label">WORKSPACE</div>
    <nav>{items.map(item => { const Icon = item.icon; return <button key={item.id} onClick={() => onChange(item.id)} className={`nav-item ${active === item.id ? "active" : ""}`}><Icon size={18}/><span>{item.label}</span></button>; })}</nav>
    <div className="sidebar-bottom">
      <div className="connection"><span className={`dot ${backendOnline ? "online" : backendOnline === false ? "offline" : ""}`}/><div><b>{backendOnline ? "Backend connected" : backendOnline === false ? "Backend unavailable" : "Checking backend"}</b><small>127.0.0.1:8000</small></div></div>
      <div className="help-note"><CircleHelp size={16}/><span>API documentation<br/><a href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer">Open Swagger UI ↗</a></span></div>
    </div>
  </aside>;
}