export type Scope =
  | "*"
  | "compliance.read"
  | "controls.read"
  | "evidence.write"
  | "policies.write"
  | "questionnaires.write"
  | "privacy.write"
  | "incidents.write"
  | "regulatory.write";

export interface ClientOptions {
  baseUrl: string;
  apiKey?: string;
  tenantId?: string;
}

export class ComplianceClient {
  constructor(private options: ClientOptions) {}

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (this.options.apiKey) headers["X-API-Key"] = this.options.apiKey;
    if (this.options.tenantId) headers["X-Tenant-ID"] = this.options.tenantId;

    return headers;
  }

  private async get(path: string) {
    const res = await fetch(`${this.options.baseUrl}${path}`, {
      headers: this.headers(),
    });
    return res.json();
  }

  private async post(path: string, body?: unknown) {
    const res = await fetch(`${this.options.baseUrl}${path}`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body || {}),
    });
    return res.json();
  }

  health() {
    return this.get("/health");
  }

  metrics() {
    return this.get("/v1/brain/metrics");
  }

  controls() {
    return this.get("/v1/controls");
  }

  evidence() {
    return this.get("/v1/evidence");
  }

  runConnector(connector: string) {
    return this.post(`/v1/connectors/${connector}/run`);
  }

  generatePolicy() {
    return this.post("/v1/policies/generate");
  }

  processQuestionnaire(questionnaireId: string) {
    return this.post(`/v1/questionnaires/${questionnaireId}/process`);
  }

  startDsar(requesterEmail: string, requestType = "access") {
    return this.post("/v1/dsar/start", {
      request_type: requestType,
      requester_email: requesterEmail,
    });
  }

  advanceDsar(dsarId: string) {
    return this.post(`/v1/dsar/${dsarId}/advance`);
  }

  triageIncident(incidentId: string) {
    return this.post(`/v1/incidents/${incidentId}/triage`);
  }

  crawlRegRadar() {
    return this.post("/v1/reg-radar/crawl");
  }

  generateReport() {
    return this.post("/v1/reports/generate");
  }

  mcpCall(tool: string, args: Record<string, unknown> = {}) {
    return this.post("/v1/mcp/call", { tool, arguments: args });
  }
}
