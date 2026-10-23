-- IOC_export.csv: one row per indicator of compromise seen by the lab.
--   ip        every attacker address, with AbuseIPDB score and country
--   sha256    every captured file, with its VirusTotal verdict
--   url       every URL an attacker made Cowrie download from
-- Demo rows from scripts/seed-demo-geo.sh are left out.
-- Run through scripts/export-ioc.sh (COPY ... TO STDOUT needs no file access).
COPY (
  SELECT * FROM (
    -- Attacker IPs
    SELECT
      'ip'                                  AS ioc_type,
      host(e.src_ip)                        AS value,
      min(e.event_time)                     AS first_seen,
      max(e.event_time)                     AS last_seen,
      count(*)                              AS event_count,
      string_agg(DISTINCT e.service, ' ' ORDER BY e.service) AS services,
      max(r.abuse_confidence_score)         AS abuse_score,
      max(r.country_code)                   AS country,
      NULL::integer                         AS vt_malicious,
      NULL::text                            AS vt_label,
      CASE WHEN r.is_public IS FALSE THEN 'private lab address: no reputation data'
           WHEN r.ip IS NULL THEN 'not looked up yet'
      END                                   AS note
    FROM events e
    LEFT JOIN ip_reputation r ON r.ip = e.src_ip
    WHERE e.source_file <> 'demo-seed'
    GROUP BY e.src_ip, r.ip, r.is_public

    UNION ALL
    -- Captured files
    SELECT
      'sha256', m.sha256, m.first_seen, m.first_seen, 1, m.service,
      NULL, NULL, m.vt_malicious, m.vt_threat_label,
      CASE WHEN m.vt_checked_at IS NULL THEN 'not checked on VirusTotal yet'
           ELSE m.vt_permalink END
    FROM malware_samples m

    UNION ALL
    -- Download URLs (Cowrie)
    SELECT
      'url', e.raw->>'url', min(e.event_time), max(e.event_time), count(*),
      'cowrie', NULL, NULL, NULL, NULL, NULL
    FROM events e
    WHERE e.event_type = 'cowrie.session.file_download'
      AND e.raw->>'url' IS NOT NULL
      AND e.source_file <> 'demo-seed'
    GROUP BY e.raw->>'url'
  ) iocs
  ORDER BY ioc_type, event_count DESC, value
) TO STDOUT WITH (FORMAT csv, HEADER true);
