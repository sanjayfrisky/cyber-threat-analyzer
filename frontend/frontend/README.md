# Cyber Threat RAG – Next.js Frontend

This is a frontend-only addition. It does not modify or replace the existing FastAPI backend.

## Requirements
- Node.js 20+
- Existing FastAPI backend running at `http://127.0.0.1:8000`

## Setup (Windows PowerShell)
```powershell
cd frontend
npm install
Copy-Item .env.local.example .env.local
npm run dev
```
Open http://localhost:3000

If your backend uses another address, update `NEXT_PUBLIC_API_BASE_URL` in `.env.local` and restart Next.js.

## Backend contract discovered in the supplied ZIP
- `POST /api/chat` – JSON `{ "prompt": "...", "session_id": "..." }`; returns Server-Sent Events with JSON `data:` events. The frontend reads `type: "chunk"` and `type: "error"`.
- `POST /api/screening` – multipart form fields `content` OR `file`, and optional `context`; accepted files are PDF, TXT, LOG, JSON; backend limit is configured by `MAX_UPLOAD_MB` (code default 15 MB).
- FastAPI built-in `GET /openapi.json` is used for connection status and route discovery.
- The current `app/main.py` does not register a `/api/health` route or any ingestion route. This frontend intentionally does not call either endpoint and does not change backend code. Ingestion can be added to the UI only after a real route is exposed by the backend.

## Notes
- Screening returns a JSON object with verdict, risk_score, confidence, threat_category, prompt_injection_detected, mitre_techniques, summary, findings, recommended_action, iocs and sources.
- Chat request field is `prompt`, not `message`.
- If browser requests fail, verify FastAPI is running and CORS includes `http://localhost:3000`.
