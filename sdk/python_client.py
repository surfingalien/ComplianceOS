from typing import Any
import requests


class ComplianceClient:
    def __init__(self, base_url: str, api_key: str = None, tenant_id: str = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id
        return headers

    def _get(self, path: str):
        return requests.get(f"{self.base_url}{path}", headers=self._headers()).json()

    def _post(self, path: str, payload: dict = None):
        return requests.post(f"{self.base_url}{path}", headers=self._headers(), json=payload or {}).json()

    def health(self):
        return self._get("/health")

    def metrics(self):
        return self._get("/v1/brain/metrics")

    def controls(self):
        return self._get("/v1/controls")

    def evidence(self):
        return self._get("/v1/evidence")

    def run_connector(self, connector: str):
        return self._post(f"/v1/connectors/{connector}/run")

    def generate_policy(self):
        return self._post("/v1/policies/generate")

    def process_questionnaire(self, questionnaire_id: str):
        return self._post(f"/v1/questionnaires/{questionnaire_id}/process")

    def start_dsar(self, requester_email: str, request_type: str = "access"):
        return self._post("/v1/dsar/start", {"request_type": request_type, "requester_email": requester_email})

    def advance_dsar(self, dsar_id: str):
        return self._post(f"/v1/dsar/{dsar_id}/advance")

    def triage_incident(self, incident_id: str):
        return self._post(f"/v1/incidents/{incident_id}/triage")

    def crawl_reg_radar(self):
        return self._post("/v1/reg-radar/crawl")

    def generate_report(self):
        return self._post("/v1/reports/generate")

    def mcp_call(self, tool: str, arguments: dict = None):
        return self._post("/v1/mcp/call", {"tool": tool, "arguments": arguments or {}})
