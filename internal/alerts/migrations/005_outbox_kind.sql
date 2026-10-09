-- Rodzaj powiadomienia w outboxie: nowy alert albo jego rozwiązanie
-- (np. agent znów wysyła heartbeat – gdy grupa agentów tego chce).
ALTER TABLE gjallarhorn.outbox ADD COLUMN kind text NOT NULL DEFAULT 'new' CHECK (kind IN ('new', 'resolved'));
