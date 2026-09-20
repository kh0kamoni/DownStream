import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Set, List, Optional
import requests
from tqdm import tqdm

try:
    from src.utils.parsers import parse_ubuntu_cve_file
except ImportError:
    def parse_ubuntu_cve_file(f): return {}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ECOSYSTEM_RELEASE_MAP = {
    "Ubuntu:20.04:LTS": "focal",
    "Ubuntu:22.04:LTS": "jammy",
    "Ubuntu:24.04:LTS": "noble",
    "Ubuntu:Pro:20.04:LTS": "focal",
    "Ubuntu:Pro:22.04:LTS": "jammy",
    "Ubuntu:Pro:24.04:LTS": "noble",
}

class UbuntuCollector:
    def __init__(self, config: dict, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.package = "linux"
        self.raw_dir = self.output_dir.parent
        # If max_target is configured, respect it; otherwise collect all candidates without arbitrary caps
        self.max_collection_target = self.config.get("pilot", {}).get("max_ubuntu_collect", None)
        
        raw_releases = self.config.get("ubuntu", {}).get("releases", ["focal", "jammy", "noble"])
        if isinstance(raw_releases, dict):
            self.target_releases: Set[str] = set(raw_releases.keys())
        elif isinstance(raw_releases, list):
            self.target_releases: Set[str] = set(raw_releases)
        else:
            self.target_releases = {"focal", "jammy", "noble"}
            
        year_range = self.config.get("pilot", {}).get("cve_year_range", [2022, 2025])
        if isinstance(year_range, list) and len(year_range) == 2:
            self.years = [str(y) for y in range(year_range[0], year_range[1] + 1)]
        else:
            self.years = [str(y) for y in self.config.get("years", [2022, 2023, 2024, 2025])]

    def _get_candidate_cves(self) -> List[str]:
        """
        Prioritize CVEs that already exist in NVD, Debian, and kernel_vulns
        so that every collected Ubuntu record maximizes cross-ecosystem alignment.
        """
        nvd_dir = self.raw_dir / "nvd"
        kv_dir = self.raw_dir / "kernel_vulns"
        deb_dir = self.raw_dir / "debian"
        
        nvd_cves = {p.stem for p in nvd_dir.glob("CVE-*.json")} if nvd_dir.exists() else set()
        kv_cves = {p.stem for p in kv_dir.glob("CVE-*.json")} if kv_dir.exists() else set()
        deb_cves = {p.stem for p in deb_dir.glob("CVE-*.json")} if deb_dir.exists() else set()
        
        # High-priority intersection: in all 3 sources
        intersection = nvd_cves & kv_cves & deb_cves
        
        # Fallback union if intersection is empty
        candidates_pool = intersection if intersection else (nvd_cves | deb_cves | kv_cves)
        
        # Filter by year
        filtered = []
        for cve in sorted(candidates_pool):
            parts = cve.split("-")
            if len(parts) >= 2 and parts[1] in self.years:
                filtered.append(cve)
                
        logger.info(f"Selected {len(filtered)} prioritized candidates (across {self.years}) for Ubuntu collection.")
        return filtered

    def _fetch_single_ubuntu_cve(self, cve_id: str, session: requests.Session) -> Optional[dict]:
        """Fetch official Canonical Ubuntu vulnerability definition for a CVE."""
        year = cve_id.split("-")[1] if "-" in cve_id else ""
        github_url = f"https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/cve/{year}/UBUNTU-{cve_id}.json"
        
        try:
            resp = session.get(github_url, timeout=6)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
            
        # Fallback to Google OSV mirror for Ubuntu
        osv_url = f"https://api.osv.dev/v1/vulns/UBUNTU-{cve_id}"
        try:
            resp = session.get(osv_url, timeout=6)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
            
        return None

    def _process_cve_data(self, cve_id: str, data: dict) -> dict:
        """Transform raw Canonical OSV record into normalized DownstreamSec Ubuntu format."""
        releases = {}
        upstream_patches = []
        notices = []
        notes = []
        priority = "unknown"
        cvss = ""

        if "affected" in data:
            for a in data.get("affected", []):
                pkg_info = a.get("package", {})
                pkg_name = pkg_info.get("name", "")
                eco = pkg_info.get("ecosystem", "")
                
                if eco in ECOSYSTEM_RELEASE_MAP and "linux" in pkg_name:
                    rel = ECOSYSTEM_RELEASE_MAP[eco]
                    if rel in self.target_releases:
                        # Prioritize base 'linux' package status if multiple flavours exist
                        if rel not in releases or pkg_name == "linux":
                            fixed_ver = ""
                            for rg in a.get("ranges", []):
                                for ev in rg.get("events", []):
                                    if "fixed" in ev:
                                        fixed_ver = ev["fixed"]
                                        
                            status_str = "released" if fixed_ver else "needed"
                            releases[rel] = {
                                "status": status_str,
                                "version": fixed_ver,
                                "fixed_version": fixed_ver,
                                "note": f"package={pkg_name}"
                            }
                            
                if priority == "unknown" and "ecosystem_specific" in a:
                    priority = a.get("ecosystem_specific", {}).get("ubuntu_priority", priority)

            # Extract USN advisories
            for rel_id in data.get("related", []):
                if rel_id.startswith("USN-") and rel_id not in notices:
                    notices.append(rel_id)

            # Extract upstream commit references
            for ref in data.get("references", []):
                url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
                if "git.kernel.org" in url and url not in upstream_patches:
                    upstream_patches.append(url)

        # Ensure all target LTS releases have a designated status
        for rel in self.target_releases:
            if rel not in releases:
                releases[rel] = {
                    "status": "not-affected",
                    "version": "",
                    "fixed_version": "",
                    "note": "unaffected in this release"
                }

        return {
            "cve_id": cve_id,
            "source": "ubuntu",
            "package": self.package,
            "releases": releases,
            "upstream_patches": upstream_patches,
            "priority": priority,
            "cvss": cvss,
            "notices": notices,
            "notes": notes
        }

    def collect(self) -> Dict[str, Path]:
        candidate_cves = self._get_candidate_cves()
        results = {}
        
        logger.info(f"Beginning parallel Ubuntu status collection (target: {self.max_collection_target} records)...")
        
        # Helper worker for ThreadPoolExecutor
        def worker(cve: str):
            out_file = self.output_dir / f"{cve}.json"
            if out_file.exists():
                try:
                    with open(out_file, "r", encoding="utf-8") as f:
                        return cve, json.load(f)
                except Exception:
                    pass
            with requests.Session() as s:
                raw_data = self._fetch_single_ubuntu_cve(cve, s)
                if raw_data:
                    return cve, self._process_cve_data(cve, raw_data)
            return cve, None

        batch_size = 100
        total_target = self.max_collection_target if self.max_collection_target is not None else len(candidate_cves)
        with tqdm(total=total_target, desc="Harvesting Ubuntu CVE records") as pbar:
            for i in range(0, len(candidate_cves), batch_size):
                if self.max_collection_target is not None and len(results) >= self.max_collection_target:
                    break
                    
                batch = candidate_cves[i:i+batch_size]
                with ThreadPoolExecutor(max_workers=25) as executor:
                    futures = [executor.submit(worker, cve) for cve in batch]
                    for future in as_completed(futures):
                        cve, processed = future.result()
                        if processed:
                            out_file = self.output_dir / f"{cve}.json"
                            with open(out_file, "w", encoding="utf-8") as f:
                                json.dump(processed, f, indent=2)
                            results[cve] = out_file
                            pbar.update(1)
                            if self.max_collection_target is not None and len(results) >= self.max_collection_target:
                                break

        logger.info(f"Successfully collected and persisted {len(results)} Ubuntu CVE records in {self.output_dir}")
        return results

if __name__ == '__main__':
    import yaml
    config_path = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\config.yaml")
    config = {}
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            
    out_dir = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\data\raw\ubuntu")
    collector = UbuntuCollector(config, out_dir)
    collector.collect()
