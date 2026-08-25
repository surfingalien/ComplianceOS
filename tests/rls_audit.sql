-- PostgreSQL RLS audit script
-- Run after migrating to PostgreSQL.

SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;

SELECT tablename, policyname, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename;

-- Example RLS policies to apply in production:
--
-- ALTER TABLE controls ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation_controls ON controls
-- USING (tenant_id = current_setting('app.tenant_id')::text);
--
-- ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation_evidence ON evidence
-- USING (tenant_id = current_setting('app.tenant_id')::text);
--
-- ALTER TABLE gaps ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation_gaps ON gaps
-- USING (tenant_id = current_setting('app.tenant_id')::text);
