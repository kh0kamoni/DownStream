import json
import logging
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List
import requests
from requests.exceptions import RequestException
from tqdm import tqdm

try:
    from src.utils.parsers import extract_git_urls
except ImportError:
    # Fallback for standalone test
    def extract_git_urls(url: str) -> List[str]: return []

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NVDCollector:
    def __init__(self, config: dict, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = self.config.get("nvd", {}).get("api_key")
        self.delay = 0.7 if self.api_key else 6.0
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.years = self.config.get("years", [2022, 2023, 2024, 2025])
        
    def _fetch_page(self, params: dict, retries=5) -> dict:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        for attempt in range(retries):
            try:
                response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
                if response.status_code in [403, 429, 503]:
                    backoff = (attempt + 1) * 5
                    logger.warning(f"Rate limited or unavailable ({response.status_code}). Retrying in {backoff}s...")
                    time.sleep(backoff)
                    continue
                response.raise_for_status()
                return response.json()
            except RequestException as e:
                backoff = (attempt + 1) * 5
                logger.error(f"Request failed: {e}. Retrying in {backoff}s...")
                time.sleep(backoff)
        return {}

    def _extract_cve_data(self, item: dict) -> dict:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        
        # Descriptions
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
                
        # Metrics
        metrics = cve.get("metrics", {})
        cvss3_score = None
        cvss3_vector = ""
        cvss3_source = ""
        attack_vector = ""
        attack_complexity = ""
        
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss_data = m.get("cvssData", {})
            cvss3_score = cvss_data.get("baseScore")
            cvss3_vector = cvss_data.get("vectorString", "")
            cvss3_source = m.get("source", "")
            attack_vector = cvss_data.get("attackVector", "")
            attack_complexity = cvss_data.get("attackComplexity", "")
            
        # CWEs
        cwe_ids = []
        for weak in cve.get("weaknesses", []):
            for desc_item in weak.get("description", []):
                if desc_item.get("lang") == "en" and desc_item.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc_item.get("value"))
                    
        # References and commits
        refs = []
        commits = []
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            refs.append({"url": url, "tags": tags})
            if "git.kernel.org" in url:
                extracted = extract_git_urls(url)
                if extracted:
                    commits.extend(extracted)
        
        # CPEs
        cpe_ranges = []
        for node in cve.get("configurations", []):
            for match in node.get("nodes", []):
                for cpe in match.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        rng = {}
                        if "versionStartIncluding" in cpe: rng["version_start"] = cpe["versionStartIncluding"]
                        if "versionEndExcluding" in cpe: rng["version_end_excl"] = cpe["versionEndExcluding"]
                        if rng: cpe_ranges.append(rng)

        return {
            "cve_id": cve_id,
            "source": "nvd",
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": desc,
            "cvss3_score": cvss3_score,
            "cvss3_vector": cvss3_vector,
            "cvss3_source": cvss3_source,
            "cwe_ids": cwe_ids,
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "references": refs,
            "cpe_version_ranges": cpe_ranges,
            "reference_commit_shas": commits
        }

    def collect_for_window(self, start_date: datetime, end_date: datetime, param_key: str, param_value: str) -> Dict[str, Path]:
        results = {}
        start_idx = 0
        results_per_page = 2000
        
        while True:
            params = {
                param_key: param_value,
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "startIndex": start_idx,
                "resultsPerPage": results_per_page
            }
            
            data = self._fetch_page(params)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
                
            for item in vulnerabilities:
                parsed = self._extract_cve_data(item)
                if not parsed["cve_id"]:
                    continue
                
                out_path = self.output_dir / f"{parsed['cve_id']}.json"
                with open(out_path, "w") as f:
                    json.dump(parsed, f, indent=2)
                results[parsed["cve_id"]] = out_path
                
            start_idx += results_per_page
            time.sleep(self.delay)
            
            if start_idx >= data.get("totalResults", 0):
                break
                
        return results

    def collect(self) -> Dict[str, Path]:
        all_results = {}
        
        strategies = [
            ("sourceIdentifier", "416baaa9-dc9f-4396-8d5f-8c081fb06d67"),
            ("virtualMatchString", "cpe:2.3:o:linux:linux_kernel")
        ]
        
        for year in self.years:
            start_year = datetime(year, 1, 1)
            end_year = datetime(year, 12, 31)
            
            current_date = start_year
            while current_date <= end_year:
                window_end = min(current_date + timedelta(days=119), end_year)
                
                for key, val in strategies:
                    logger.info(f"Fetching {key}={val} for window {current_date.date()} to {window_end.date()}")
                    res = self.collect_for_window(current_date, window_end, key, val)
                    all_results.update(res)
                    
                current_date = window_end + timedelta(days=1)
                
        logger.info(f"Fetched {len(all_results)} CVEs from NVD across configured years.")
        return all_results

if __name__ == '__main__':
    import yaml
    config_path = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\config.yaml")
    config = {}
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
            
    out_dir = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\data\raw\nvd")
    collector = NVDCollector(config, out_dir)
    collector.collect()
