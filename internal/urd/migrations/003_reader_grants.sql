-- Panel (rola urd_reader) czyta spis archiwum i może tylko zlecić weryfikację.
-- Rolę zakłada skrypt deploy/lab/saga/init/10-roles.sh; bez niej (np. w testach)
-- uprawnienia są pomijane.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') THEN
        GRANT USAGE ON SCHEMA urd TO urd_reader;
        GRANT SELECT ON ALL TABLES IN SCHEMA urd TO urd_reader;
        GRANT UPDATE (verify_requested_at, verify_requested_by) ON urd.archiver_state TO urd_reader;
        ALTER DEFAULT PRIVILEGES IN SCHEMA urd GRANT SELECT ON TABLES TO urd_reader;
    END IF;
END
$$;
