-- The events list is newest first: an index in its order (read backwards) lets a page stop after its rows instead
-- of sorting every event. With `count` it also covers the overview's sums over recent hours (the key's other columns
-- are part of every index of a WITHOUT ROWID table). It replaces the index on `hour` alone.
CREATE INDEX event_hour_order ON event (hour, ip, what, count);
DROP INDEX event_hour;
