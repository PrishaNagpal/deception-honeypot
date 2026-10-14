-- Honeypot database schema (Track B).
--
-- Postgres runs this file once, on the first start of hp-db, when the pg_data
-- volume is empty. Editing it later changes nothing until the volume is
-- recreated:
--   docker compose down postgres && docker volume rm deception-honeypot_pg_data
--
-- Who writes what:
--   events           Manya's log parser
--   ip_reputation    Jeevika's AbuseIPDB enrichment
--   malware_samples  the parser inserts the row, Jeevika's VirusTotal
--                    enrichment fills the vt_ columns
--
-- All timestamps are timestamptz and mean one exact instant. The logs are UTC.


-- ---------------------------------------------------------------------------
-- events: one row per thing an attacker did.
-- ---------------------------------------------------------------------------
CREATE TABLE events (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- When. event_time is when the attacker did it, taken from the log line.
    -- Flask (+00:00) and Cowrie (Z) carry a zone. Dionaea timestamps have no
    -- zone, so the parser appends Z before inserting (that container runs in
    -- UTC). ingested_at is when the parser inserted the row; the gap between
    -- the two shows parser lag.
    event_time   timestamptz NOT NULL,
    ingested_at  timestamptz NOT NULL DEFAULT now(),

    -- What. service is which honeypot. event_type depends on the service:
    --   flask-http  http_login, http_signup
    --   cowrie      Cowrie's own eventid, unchanged, for example
    --               cowrie.session.connect, cowrie.login.failed,
    --               cowrie.login.success, cowrie.command.input,
    --               cowrie.session.closed
    --   dionaea     ftp.connection  one per log line (source_seq 0): the
    --                               connection itself
    --               ftp.login       one per entry in credentials[]; fills
    --                               username and password
    --               ftp.command     one per entry in ftp.commands[]; fills
    --                               command, for example 'USER admin'
    --   So one Dionaea line becomes several rows. To count Dionaea
    --   connections, filter on event_type = 'ftp.connection' instead of
    --   counting all rows.
    service      text NOT NULL
                 CHECK (service IN ('flask-http', 'cowrie', 'dionaea')),
    event_type   text NOT NULL,

    -- Who. src_ip joins to ip_reputation.ip. src_port is NULL for Flask,
    -- which does not log it. session_id is Cowrie's session, tying the lines
    -- of one SSH visit together; NULL for the other services.
    src_ip       inet NOT NULL,
    src_port     integer CHECK (src_port BETWEEN 0 AND 65535),
    session_id   text,

    -- Attacker input. username and password are the attacker's guesses,
    -- stored as plain text on purpose: they are what we analyse. command is
    -- Cowrie's typed input or an FTP command with its arguments.
    username     text,
    password     text,
    command      text,

    -- Flask only. NULL for the other services.
    http_method  text,
    http_path    text,
    user_agent   text,
    email        text,

    -- Flask's tags such as sqli_like or oversized_payload. Empty for the
    -- other services. Filter with:  'sqli_like' = ANY (tags)
    tags         text[] NOT NULL DEFAULT '{}',

    -- The complete original log line. Anything without its own column
    -- (Cowrie's hassh, dst_port, duration, ...) can be queried from here,
    -- for example:  raw->>'hassh'
    raw          jsonb NOT NULL,

    -- Where the row came from. These exist for the duplicate rule below.
    --   source_file     path the line was read from, for humans
    --   source_file_id  fingerprint of that file: a hash of its first line.
    --                   A rotated or recreated file at the same path gets a
    --                   different fingerprint.
    --   source_offset   byte offset where the line starts in the file
    --   source_seq      which row this is among the rows made from one line:
    --                   0, 1, 2, ... Always 0 for Flask and Cowrie.
    source_file     text     NOT NULL,
    source_file_id  text     NOT NULL,
    source_offset   bigint   NOT NULL,
    source_seq      smallint NOT NULL DEFAULT 0,

    -- Duplicate rule: a row is identified by where it was read from, not by
    -- what it says. The parser inserts with ON CONFLICT DO NOTHING.
    --   * Two events that look identical (same IP, same password, same
    --     second) sit on different lines, so they have different offsets and
    --     both are kept.
    --   * Reading the same line again, for example after a parser restart,
    --     produces the same key and is skipped.
    CONSTRAINT events_source_position_key
        UNIQUE (service, source_file_id, source_offset, source_seq)
);

-- Every dashboard panel filters on the time range.
CREATE INDEX events_event_time_idx         ON events (event_time);
-- Top attackers, one IP's history, joins to ip_reputation.
CREATE INDEX events_src_ip_event_time_idx  ON events (src_ip, event_time);
-- Per-honeypot panels.
CREATE INDEX events_service_event_time_idx ON events (service, event_time);


-- ---------------------------------------------------------------------------
-- ip_reputation: one row per IP address, filled by Jeevika from AbuseIPDB.
--
-- Join with:  events.src_ip = ip_reputation.ip
-- There is no foreign key from events, because events arrive before anyone
-- has looked the IP up. Use a LEFT JOIN so events without a lookup still show.
-- ---------------------------------------------------------------------------
CREATE TABLE ip_reputation (
    ip                      inet PRIMARY KEY,

    -- AbuseIPDB's verdict.
    abuse_confidence_score  smallint
                            CHECK (abuse_confidence_score BETWEEN 0 AND 100),
    total_reports           integer,
    last_reported_at        timestamptz,

    -- Where the address is and who owns it. country_code is the ISO code
    -- (IN, US, ...). is_public is false for private addresses such as
    -- 172.28.0.1, which have no country.
    country_code            char(2),
    country_name            text,
    isp                     text,
    domain                  text,
    usage_type              text,
    is_public               boolean,

    -- When the lookup was done, so stale rows can be refreshed, and the full
    -- API response.
    checked_at              timestamptz NOT NULL DEFAULT now(),
    raw                     jsonb
);


-- ---------------------------------------------------------------------------
-- malware_samples: one row per distinct captured file.
--
-- The parser inserts the row (sha256, service, file_path, file_size,
-- first_seen, and first_src_ip if known). Jeevika's enrichment then fills the
-- vt_ columns from VirusTotal. The same file dropped twice is still one row.
-- ---------------------------------------------------------------------------
CREATE TABLE malware_samples (
    -- SHA-256 of the file contents, as 64 lowercase hex characters.
    sha256           char(64) PRIMARY KEY
                     CHECK (sha256 ~ '^[0-9a-f]{64}$'),

    -- Written by the parser. service is which honeypot captured the file,
    -- file_path is where it sits under data/, file_size is in bytes.
    service          text,
    file_path        text,
    file_size        bigint,
    first_seen       timestamptz NOT NULL DEFAULT now(),
    first_src_ip     inet,

    -- Written by Jeevika's VirusTotal enrichment. The four counts are how
    -- many antivirus engines gave each verdict. vt_checked_at is NULL until
    -- the file has been looked up, so "not yet checked" is:
    --   WHERE vt_checked_at IS NULL
    vt_malicious     integer,
    vt_suspicious    integer,
    vt_harmless      integer,
    vt_undetected    integer,
    vt_threat_label  text,
    vt_permalink     text,
    vt_checked_at    timestamptz,
    vt_raw           jsonb
);
