-- Removes everything scripts/seed-demo-geo.sh added. Real data is never touched:
-- demo events have source_file = 'demo-seed', demo IP lookups have
-- raw->>'demo_seed' = 'true'.
DELETE FROM events WHERE source_file = 'demo-seed';
DELETE FROM ip_reputation WHERE raw->>'demo_seed' = 'true';
