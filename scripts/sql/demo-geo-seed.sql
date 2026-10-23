-- DEMO DATA for the world-map panel. Not real attacks.
--
-- Lab traffic comes from private addresses (172.28.0.1 and friends), which have
-- no country, so the map would stay empty. This adds fake attackers from the
-- reserved documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24;
-- RFC 5737: they never belong to anyone) with made-up countries, so the panel can
-- be shown. Remove them with:  bash scripts/seed-demo-geo.sh --remove
\set ON_ERROR_STOP on
BEGIN;

-- Safe to run twice.
DELETE FROM events WHERE source_file = 'demo-seed';
DELETE FROM ip_reputation WHERE raw->>'demo_seed' = 'true';

CREATE TEMP TABLE demo_ips (idx int, ip inet, cc char(2), country text, score int, reports int, n int);
INSERT INTO demo_ips VALUES
  (1,  '203.0.113.10', 'CN', 'China',          96, 412, 40),
  (2,  '203.0.113.11', 'RU', 'Russia',         91, 288, 30),
  (3,  '198.51.100.7', 'US', 'United States',  54,  35, 18),
  (4,  '198.51.100.8', 'BR', 'Brazil',         77,  96, 14),
  (5,  '192.0.2.21',   'IN', 'India',          33,  12, 10),
  (6,  '192.0.2.22',   'DE', 'Germany',        61,  47,  9),
  (7,  '203.0.113.30', 'NL', 'Netherlands',    88, 150,  8),
  (8,  '198.51.100.40','KR', 'South Korea',    72,  64,  7),
  (9,  '192.0.2.50',   'VN', 'Vietnam',        69,  58,  6),
  (10, '203.0.113.60', 'ID', 'Indonesia',      41,  20,  5),
  (11, '198.51.100.90','ZA', 'South Africa',   29,   9,  4),
  (12, '192.0.2.77',   'AU', 'Australia',      18,   4,  3);

INSERT INTO ip_reputation
  (ip, abuse_confidence_score, total_reports, country_code, country_name, isp,
   usage_type, is_public, checked_at, raw)
SELECT ip, score, reports, cc, country, 'DEMO DATA (not a real address)', 'Demo',
       true, now(), '{"demo_seed": true}'::jsonb
FROM demo_ips;

-- Spread the events over the last 55 minutes, never the last 2, so the
-- "attack in progress" phone alert is not triggered by demo data.
INSERT INTO events
  (event_time, service, event_type, src_ip, session_id, username, password,
   command, http_method, http_path, tags, raw, source_file, source_file_id, source_offset)
SELECT
  now() - make_interval(secs => 120 + (d.idx * 97 + g * 53) % 3180),
  s.service,
  s.event_type,
  d.ip,
  CASE WHEN s.service = 'cowrie' THEN 'demo' || d.idx END,
  CASE WHEN s.event_type <> 'cowrie.command.input' THEN (ARRAY['root','admin','test','oracle'])[1 + g % 4] END,
  CASE WHEN s.event_type <> 'cowrie.command.input' THEN (ARRAY['123456','admin','password','root'])[1 + (g / 2) % 4] END,
  CASE WHEN s.event_type = 'cowrie.command.input' THEN 'uname -a' END,
  CASE WHEN s.service = 'flask-http' THEN 'POST' END,
  CASE WHEN s.service = 'flask-http' THEN '/login' END,
  '{}',
  '{"demo_seed": true}'::jsonb,
  'demo-seed', 'demo-seed', d.idx * 1000 + g
FROM demo_ips d
CROSS JOIN LATERAL generate_series(1, d.n) AS g
CROSS JOIN LATERAL (
  SELECT * FROM (VALUES
    (0, 'cowrie',     'cowrie.login.failed'),
    (1, 'flask-http', 'http_login'),
    (2, 'dionaea',    'ftp.login'),
    (3, 'cowrie',     'cowrie.command.input')
  ) AS t(k, service, event_type) WHERE t.k = g % 4
) s;

COMMIT;
SELECT count(*) AS demo_ips, (SELECT count(*) FROM events WHERE source_file = 'demo-seed') AS demo_events FROM demo_ips;
