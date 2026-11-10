-- Pruning deletes the `what`s no event refers to: without this index that is a scan of every event per `what`,
-- which on a large database held the write lock for hours. IF NOT EXISTS: databases where it was added by hand.
CREATE INDEX IF NOT EXISTS event_what ON event (what);
