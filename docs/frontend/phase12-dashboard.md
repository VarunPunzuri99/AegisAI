# AegisAI Frontend — Phase 12

Security observability console for the existing backend pipeline.

## Router

Next.js **App Router** (`frontend/app/`).

## Routes

| Route | Purpose |
|-------|---------|
| `/` | Redirects to `/dashboard` |
| `/dashboard` | Security overview + eval metrics + activity |
| `/scanner` | Free-text inspect + evidence chain |
| `/attack-playground` | Predefined attacks → live pipeline |
| `/evaluation` | Offline vs live metrics |
| `/detection-analytics` | Fusion / conflicts / confusion |
| `/policy` | Read-only policy bands |
| `/tool-security` | Tool registry + firewall controls |
| `/audit` | Audit viewer (empty adapter — API missing) |

## API consumed

| Method | Path | Notes |
|--------|------|-------|
| GET | `/health` | Liveness |
| POST | `/api/v1/inspect` | Full pipeline view model |
| POST | `/api/v1/scans` | Metadata-only scan record |
| GET | `/api/v1/dashboard/evaluation` | Reads eval JSON from disk |
| GET | `/api/v1/dashboard/playground` | Attack scenarios |
| GET | `/api/v1/dashboard/policy` | Read-only policy |
| GET | `/api/v1/dashboard/tools` | Registry |
| GET | `/api/v1/dashboard/status` | Config status (no key exposure) |
| GET | `/api/v1/dashboard/activity` | Scan metadata list |

## Missing backend endpoints

- Structured audit event list / filter API
- Persisting inspect decisions onto Scan rows (activity table shows metadata only)
- Live Groq health probe (status is configuration-only by design)

## Security notes

- Frontend never decides risk/policy/tool outcomes.
- No Groq calls from the browser.
- No API keys in frontend env.
- Evaluation metrics labeled as dataset-only.

## Commands

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run dev
```
