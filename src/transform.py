import duckdb
from pathlib import Path

DB_PATH = Path("data/oss_pulse.duckdb")

def build_medallion_layers() -> None:
    con = duckdb.connect(str(DB_PATH))
    con.execute("""
        CREATE OR REPLACE TABLE silver_vulnerabilities AS
        SELECT DISTINCT
            vuln_id,
            LOWER(TRIM(package_name)) AS package_name,
            CAST(published_at AS TIMESTAMP) AS published_at,
            CAST(modified_at AS TIMESTAMP) AS modified_at,
            DATE_DIFF('day', CAST(published_at AS TIMESTAMP), CAST(modified_at AS TIMESTAMP)) AS remediation_lag_days,
            summary,
            affected_ranges_count
        FROM read_parquet('data/bronze/osv_vulnerabilities.parquet')
        WHERE vuln_id IS NOT NULL;
    """)
    con.execute("""
        CREATE OR REPLACE TABLE silver_repos AS
        SELECT
            LOWER(TRIM(package_name)) AS package_name,
            repo_full_name,
            stars,
            open_issues_count,
            forks_count,
            days_since_last_push,
            top_contributor_share_pct,
            active_contributors_sampled,
            ingested_at
        FROM read_parquet('data/bronze/github_repos.parquet');
    """)
    con.execute("""
        CREATE OR REPLACE TABLE gold_dependency_risk AS
        WITH vuln_agg AS (
            SELECT
                package_name,
                COUNT(vuln_id) AS total_historical_cves,
                COUNT(CASE WHEN published_at >= CURRENT_TIMESTAMP - INTERVAL '365 days' THEN 1 END) AS recent_cves_1yr,
                ROUND(AVG(remediation_lag_days), 1) AS avg_remediation_days,
                MAX(affected_ranges_count) AS max_blast_radius
            FROM silver_vulnerabilities
            GROUP BY package_name
        )
        SELECT
            r.package_name,
            r.repo_full_name,
            r.stars,
            r.open_issues_count,
            r.days_since_last_push,
            r.top_contributor_share_pct AS bus_factor_concentration_pct,
            COALESCE(v.total_historical_cves, 0) AS total_cves,
            COALESCE(v.recent_cves_1yr, 0) AS cves_last_12m,
            COALESCE(v.avg_remediation_days, 0.0) AS avg_mttr_days,
            ROUND(
                (r.top_contributor_share_pct * 0.4) +
                (LEAST(r.days_since_last_push, 100) * 0.3) +
                (COALESCE(v.recent_cves_1yr, 0) * 6.0),
                1
            ) AS composite_risk_score,
            CASE
                WHEN r.top_contributor_share_pct >= 65 AND r.days_since_last_push >= 30 THEN 'CRITICAL_BURNOUT_RISK'
                WHEN COALESCE(v.recent_cves_1yr, 0) >= 3 OR COALESCE(v.total_historical_cves, 0) >= 15 THEN 'ELEVATED_SECURITY_DEBT'
                ELSE 'HEALTHY_SUPPLY_CHAIN'
            END AS risk_classification
        FROM silver_repos r
        LEFT JOIN vuln_agg v ON r.package_name = v.package_name
        ORDER BY composite_risk_score DESC;
    """)
    con.sql("SELECT package_name, bus_factor_concentration_pct, total_cves, composite_risk_score, risk_classification FROM gold_dependency_risk").show()
    con.close()

if __name__ == "__main__":
    build_medallion_layers()
