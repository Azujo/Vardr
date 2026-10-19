-- Czas wpisania segmentu do spisu: segment przyjęty po przywróceniu kopii
-- (Reconcile) ma starą godzinę, a manifest obejmie go dopiero przy
-- zamknięciu bieżącej godziny – weryfikacja liczy zaległość od rejestracji.
ALTER TABLE urd.segments ADD COLUMN registered_at timestamptz;
