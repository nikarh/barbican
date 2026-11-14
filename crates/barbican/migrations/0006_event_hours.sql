-- The events of each hour summed per rule, kept by triggers as events are added, counted and deleted: the overview
-- reads a month of them (some 700 rows a rule) instead of summing and sorting every event of the month.
CREATE TABLE event_hour (
    hour INTEGER NOT NULL,
    rule INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, rule)
) STRICT, WITHOUT ROWID;

INSERT INTO event_hour (hour, rule, count) SELECT hour, rule, sum(count) FROM event GROUP BY hour, rule;

CREATE TRIGGER event_hour_insert AFTER INSERT ON event BEGIN
    INSERT INTO event_hour (hour, rule, count) VALUES (new.hour, new.rule, new.count)
        ON CONFLICT (hour, rule) DO UPDATE SET count = count + excluded.count;
END;

-- An event's hour and rule are part of its key, and never change: only its count does.
CREATE TRIGGER event_hour_update AFTER UPDATE OF count ON event BEGIN
    UPDATE event_hour SET count = count + new.count - old.count WHERE hour = new.hour AND rule = new.rule;
END;

CREATE TRIGGER event_hour_delete AFTER DELETE ON event BEGIN
    UPDATE event_hour SET count = count - old.count WHERE hour = old.hour AND rule = old.rule;
    DELETE FROM event_hour WHERE hour = old.hour AND rule = old.rule AND count = 0;
END;

-- The addresses list sorted by hits or by first seen walks these instead of sorting every address.
CREATE INDEX ip_hits ON ip (hits);
CREATE INDEX ip_first_seen ON ip (first_seen);
