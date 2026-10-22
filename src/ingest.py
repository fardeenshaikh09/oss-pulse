import json
from datetime import datetime, timezone
from pathlib import Path
import httpx
import polars as pl
from pydantic import BaseModel, Field, ValidationError

BRONZE_DIR = Path("data/bronze")
DLQ_DIR = Path("data/dlq")
BRONZE_DIR.mkdir(parents=True, exist_ok=True)
DLQ_DIR.mkdir(parents=True, exist_ok=True)

TARGETS = [
    ("requests", "psf/requests"),
    ("cryptography", "pyca/cryptography"),
    ("pydantic", "pydantic/pydantic"),
    ("fastapi", "fastapi/fastapi"),
    ("urllib3", "urllib3/urllib3"),
    ("jinja2", "pallets/jinja"),
    ("paramiko", "paramiko/paramiko"),
    ("pyyaml", "yaml/pyyaml"),
]

class VulnerabilityContract(BaseModel):
    vuln_id: str = Field(alias="id")
    package_name: str
    published_at: datetime
    modified_at: datetime
    summary: str = "No summary provided"
    affected_ranges_count: int = 1
    ingested_at: datetime

class RepoMetadataContract(BaseModel):
    package_name: str
    repo_full_name: str
    stars: int
    open_issues_count: int
    forks_count: int
    days_since_last_push: int
    top_contributor_share_pct: float
    active_contributors_sampled: int
    ingested_at: datetime

def write_to_dlq(source: str, payload: dict, error_msg: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    dlq_file = DLQ_DIR / f"dlq_{source}_{timestamp}.json"
    dlq_file.write_text(json.dumps({"error": error_msg, "payload": payload}, indent=2))

def ingest_osv_vulnerabilities(client: httpx.Client) -> list[dict]:
    valid_rows = []
    now = datetime.now(timezone.utc)
    for pkg_name, _ in TARGETS:
        resp = client.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": pkg_name, "ecosystem": "PyPI"}},
            timeout=15.0,
        )
        resp.raise_for_status()
        for v in resp.json().get("vulns", []):
            try:
                record = VulnerabilityContract(
                    id=v["id"],
                    package_name=pkg_name,
                    published_at=v.get("published", now.isoformat()),
                    modified_at=v.get("modified", now.isoformat()),
                    summary=v.get("summary", "Unclassified vulnerability")[:200],
                    affected_ranges_count=max(1, len(v.get("affected", []))),
                    ingested_at=now,
                )
                valid_rows.append(record.model_dump())
            except ValidationError as err:
                write_to_dlq("osv", v, str(err))
    return valid_rows

def ingest_github_metrics(client: httpx.Client) -> list[dict]:
    valid_rows = []
    now = datetime.now(timezone.utc)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "OSS-Pulse-Pipeline"}
    for pkg_name, repo_slug in TARGETS:
        repo_resp = client.get(f"https://api.github.com/repos/{repo_slug}", headers=headers, timeout=15.0)
        if repo_resp.status_code != 200:
            continue
        repo_data = repo_resp.json()
        contrib_resp = client.get(
            f"https://api.github.com/repos/{repo_slug}/contributors?per_page=10",
            headers=headers,
            timeout=15.0,
        )
        contribs = contrib_resp.json() if contrib_resp.status_code == 200 and isinstance(contrib_resp.json(), list) else []
        total_sampled_commits = sum(c.get("contributions", 0) for c in contribs) or 1
        top_commits = contribs[0].get("contributions", 0) if contribs else 0
        top_share = round((top_commits / total_sampled_commits) * 100, 2)
        pushed_at = datetime.fromisoformat(repo_data["pushed_at"].replace("Z", "+00:00"))
        days_inactive = max(0, (now - pushed_at).days)
        try:
            record = RepoMetadataContract(
                package_name=pkg_name,
                repo_full_name=repo_slug,
                stars=repo_data.get("stargazers_count", 0),
                open_issues_count=repo_data.get("open_issues_count", 0),
                forks_count=repo_data.get("forks_count", 0),
                days_since_last_push=days_inactive,
                top_contributor_share_pct=top_share,
                active_contributors_sampled=len(contribs),
                ingested_at=now,
            )
            valid_rows.append(record.model_dump())
        except ValidationError as err:
            write_to_dlq("github", repo_data, str(err))
    return valid_rows

if __name__ == "__main__":
    with httpx.Client() as http_client:
        vuln_data = ingest_osv_vulnerabilities(http_client)
        repo_data = ingest_github_metrics(http_client)
    if vuln_data:
        pl.DataFrame(vuln_data).write_parquet(BRONZE_DIR / "osv_vulnerabilities.parquet")
    if repo_data:
        pl.DataFrame(repo_data).write_parquet(BRONZE_DIR / "github_repos.parquet")
    print("Bronze ingestion complete.")
