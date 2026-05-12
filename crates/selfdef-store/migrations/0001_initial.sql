-- Initial schema for the selfdef hot event store.
-- Applied when user_version = 0; sets user_version = 1 on success.

CREATE TABLE IF NOT EXISTS events (
    id              BLOB    NOT NULL PRIMARY KEY,    -- UUIDv7, 16 bytes
    schema          INTEGER NOT NULL,
    time_ns         INTEGER NOT NULL,                -- unix epoch nanoseconds
    category_uid    INTEGER NOT NULL,
    class_uid       INTEGER NOT NULL,
    activity_id     INTEGER NOT NULL,
    type_uid        INTEGER NOT NULL,
    severity_id     INTEGER NOT NULL,
    status_id       INTEGER,
    host_tag        TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    sequence        INTEGER NOT NULL,
    payload         TEXT    NOT NULL                 -- serde_json of full Event
) STRICT;

CREATE INDEX IF NOT EXISTS idx_events_time     ON events(time_ns DESC);
CREATE INDEX IF NOT EXISTS idx_events_class    ON events(class_uid, time_ns DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity_id, time_ns DESC);
CREATE INDEX IF NOT EXISTS idx_events_host     ON events(host_tag, time_ns DESC);
CREATE INDEX IF NOT EXISTS idx_events_source   ON events(source, time_ns DESC);
