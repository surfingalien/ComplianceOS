# ComplianceOS — Full Integrated Platform

A single deployable reference implementation that wires together a full compliance
platform: control framework, evidence collection, control testing, AI-assisted
policy and questionnaire generation, GDPR DSAR workflows, incident response tied
to a 50-state breach notification matrix, regulatory change radar, vendor risk,
executive reporting, an MCP tool surface, and a central **Neuralink Brain**
telemetry layer for tracking, correlation, and anomaly detection.

External connectors (AWS, Okta, GitHub, HR) are implemented as a connector
framework with local simulated responses, so the whole system runs immediately
with no external credentials. Swap `simulate_connector()` in `app/main.py` for
real API calls when you're ready to point it at live systems.

## Project Structure

```text
ComplianceOS/
├── app/
│   ├── main.py          # FastAPI app: all models, routes, business logic
│   └── console.html     # Built-in operator console (single-page UI)
├── sdk/
│   ├── python_client.py # Python SDK
│   └── ts_client.ts     # TypeScript SDK
├── tests/
│   ├── load_test_k6.js  # k6 load test
│   └── rls_audit.sql    # PostgreSQL row-level-security audit + example policies
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000`.

## Run with Docker

```bash
docker compose up --build
```

## First Steps

Click through the console buttons in order the first time:

1. **Seed Full System** — creates the default tenant, frameworks (SOC 2, ISO
   27001, HIPAA, GDPR), the control catalog with framework mappings, the
   50-state breach notification matrix, the answer library, regulatory
   sources, and one sample questionnaire/incident/vendor/audit engagement.
2. **Load Metrics** — pulls live counts from the Neuralink Brain.
3. **Run AWS / Okta / GitHub Connector** — simulates evidence collection and
   scores the resulting evidence.
4. **Seed Default Test** — creates and immediately runs a control test against
   the Okta evidence.
5. **Generate Policy AI** — drafts a policy document from the current control
   catalog.
6. **Process Questionnaire AI** — answers the seeded questionnaire from the
   answer library using confidence-scored retrieval.
7. **Start GDPR DSAR** / **Advance DSAR** — walks a 10-step GDPR DSAR workflow,
   attaching evidence to each completed step.
8. **Triage Incident** — matches the seeded incident's affected states against
   the breach matrix to compute legal obligations.
9. **Crawl Reg Radar** — simulates detecting regulatory updates and files them
   for expert review.
10. **Generate Executive Report** — rolls up controls, gaps, and evidence into
    a readiness score.
11. **MCP Tools** / **Brain Anomalies** — inspect the MCP tool catalog and the
    Brain's request-volume anomaly detector.

## Authentication

Authentication is disabled by default (`AUTH_ENABLED=false`), so every request
uses a single default tenant with full scope — convenient for local
evaluation. Set `AUTH_ENABLED=true` and pass an `X-API-Key` header (seeded as
`demo-key` after running the full seed) plus an `X-Tenant-ID` header to
exercise the scoped multi-tenant path.

## API Docs

- Swagger UI: `http://localhost:8000/docs` (loads its UI from a CDN; won't
  render in network-restricted sandboxes, but works in any normal deployment)
- OpenAPI JSON: `http://localhost:8000/v1/platform/openapi`

## SDKs

`sdk/python_client.py` and `sdk/ts_client.ts` wrap the REST API with
typed/convenience methods. The Python client needs `requests`
(`pip install requests`) — it's a separate consumer-side dependency, not
part of the server's `requirements.txt`.

## Load Testing & RLS Audit

```bash
k6 run tests/load_test_k6.js
```

`tests/rls_audit.sql` lists the current row-level-security state on Postgres
and includes example tenant-isolation policies to apply before going to
production with a shared Postgres database.

## Production Checklist

- Switch `DATABASE_URL` to PostgreSQL and apply the RLS policies from
  `tests/rls_audit.sql`.
- Set `AUTH_ENABLED=true` and issue real per-tenant API keys.
- Replace the simulated connectors with real AWS/Okta/GitHub/HR integrations.
- Put a real secrets manager, TLS termination, and rate limiting in front of
  the API.
- Move evidence payloads to object storage instead of inline JSON columns.
- Add OpenTelemetry export alongside (or instead of) the built-in Neuralink
  Brain telemetry table.
- Add backup/disaster recovery for the database.
