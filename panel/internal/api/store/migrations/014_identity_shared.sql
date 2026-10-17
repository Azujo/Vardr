-- Konta wspólne urządzeń (przegląd etapu 7): konto z tej listy bez domeny
-- (admin na routerze MikroTik, na FortiGate, root na urządzeniu) dostaje
-- tożsamość „urządzenie\konto” zamiast łączyć się z domenowym „admin”.
CREATE TABLE identity_shared_accounts (
    account     text        PRIMARY KEY CHECK (account = lower(account) AND length(account) BETWEEN 1 AND 320),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL
);

INSERT INTO identity_shared_accounts (account, created_by)
VALUES ('admin', 'system'), ('administrator', 'system'), ('root', 'system'), ('guest', 'system');
