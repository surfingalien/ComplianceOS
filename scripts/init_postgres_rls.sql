-- Example PostgreSQL RLS initialization for production.
-- Apply after creating the schema.

ALTER TABLE controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE review_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_controls ON controls
USING (tenant_id = current_setting('app.tenant_id')::text);

CREATE POLICY tenant_isolation_evidence ON evidence
USING (tenant_id = current_setting('app.tenant_id')::text);

CREATE POLICY tenant_isolation_tests ON tests
USING (tenant_id = current_setting('app.tenant_id')::text);

CREATE POLICY tenant_isolation_test_runs ON test_runs
USING (tenant_id = current_setting('app.tenant_id')::text);

CREATE POLICY tenant_isolation_gaps ON gaps
USING (tenant_id = current_setting('app.tenant_id')::text);

CREATE POLICY tenant_isolation_review_items ON review_items
USING (tenant_id = current_setting('app.tenant_id')::text);

CREATE POLICY tenant_isolation_telemetry_events ON telemetry_events
USING (tenant_id = current_setting('app.tenant_id')::text);
