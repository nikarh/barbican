-- `fetched` is a feed's last attempt, failed or not. Also kept: when it was last fetched without an error (its list
-- new or unchanged), and when its list last changed.
ALTER TABLE feed ADD COLUMN succeeded INTEGER;
ALTER TABLE feed ADD COLUMN changed INTEGER;
UPDATE feed SET succeeded = fetched, changed = fetched WHERE fetched IS NOT NULL AND error IS NULL;
