-- Od kiedy agent jest w obecnej grupie – według obserwacji archiwizatora
-- (tabela należy do archiwizatora, panel jej nie zmieni). Wykluczenie grupy
-- z archiwum obejmuje agenta dopiero po karencji od wejścia do grupy, więc
-- przeniesienie agenta do wyłączonej grupy (albo rejestracja tokenem z taką
-- grupą) nie omija karencji osłabienia polityki.
CREATE TABLE urd.group_membership (
    agent_id text PRIMARY KEY,
    group_id bigint NOT NULL,
    since    timestamptz NOT NULL
);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') THEN
        GRANT SELECT ON urd.group_membership TO urd_reader;
    END IF;
END
$$;
