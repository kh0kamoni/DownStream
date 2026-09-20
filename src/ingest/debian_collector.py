import json
import logging
import time
from pathlib import Path
from typing import Dict
from datetime import datetime, timedelta
import requests
from tqdm import tqdm

try:
    from src.utils.parsers import parse_debian_json_entry, parse_debian_cve_list_entry, extract_git_urls
    from src.utils.git_utils import clone_or_pull
except ImportError:
    def parse_debian_json_entry(d, r): return {}
    def parse_debian_cve_list_entry(l): return {}
    def extract_git_urls(s): return []
    def clone_or_pull(r, d, s): pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DebianCollector:
    def __init__(self, config: dict, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.package = "linux"
        self.json_url = "https://security-tracker.debian.org/tracker/data/json"
        self.git_url = "https://salsa.debian.org/security-tracker-team/security-tracker.git"
        self.cache_file = self.output_dir.parent / "debian_tracker.json"
        self.git_dir = self.output_dir.parent / "debian_git"
        raw_releases = self.config.get("debian", {}).get("releases", ["bullseye", "bookworm", "trixie", "sid"])
        if isinstance(raw_releases, dict):
            self.target_releases = set(raw_releases.keys())
        elif isinstance(raw_releases, list):
            self.target_releases = set(raw_releases)
        else:
            self.target_releases = {"bullseye", "bookworm", "trixie", "sid"}
            
        year_range = self.config.get("pilot", {}).get("cve_year_range", [2022, 2025])
        if isinstance(year_range, list) and len(year_range) == 2:
            self.years = [str(y) for y in range(year_range[0], year_range[1] + 1)]
        else:
            self.years = [str(y) for y in self.config.get("years", [2022, 2023, 2024, 2025])]

    def _get_json_data(self) -> dict:
        fetch_needed = True
        if self.cache_file.exists():
            mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            if datetime.now() - mtime < timedelta(hours=24):
                fetch_needed = False
                
        if fetch_needed:
            logger.info("Downloading Debian Security Tracker JSON...")
            response = requests.get(self.json_url)
            response.raise_for_status()
            with open(self.cache_file, "w") as f:
                json.dump(response.json(), f)
                
        with open(self.cache_file, "r") as f:
            return json.load(f)

    def collect(self) -> Dict[str, Path]:
        logger.info(f"Cloning/Pulling Debian security-tracker git to {self.git_dir}")
        clone_or_pull(self.git_url, self.git_dir, shallow=True)
        
        tracker_data = self._get_json_data()
        package_data = tracker_data.get(self.package, {})
        
        # Git parsing for notes/commits
        cve_list_path = self.git_dir / "data" / "CVE" / "list"
        git_infos = {}
        if cve_list_path.exists():
            with open(cve_list_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            current_cve = None
            for line in lines:
                if line.startswith("CVE-"):
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) > 0:
                        current_cve = parts[0]
                        if current_cve not in git_infos:
                            git_infos[current_cve] = {"upstream_commits": [], "notes": []}
                elif line.startswith("\tNOTE:") and current_cve:
                    note = line.strip()[6:].strip()
                    git_infos[current_cve]["notes"].append(note)
                    urls = extract_git_urls(note)
                    git_infos[current_cve]["upstream_commits"].extend(urls)
        
        results = {}
        for cve_id, releases_data in tqdm(package_data.items(), desc="Processing Debian CVEs"):
            year_part = cve_id.split("-")[1] if "-" in cve_id else ""
            if year_part not in self.years:
                continue
                
            releases = {}
            for rel, r_data in releases_data.get("releases", {}).items():
                if rel in self.target_releases:
                    releases[rel] = {
                        "status": r_data.get("status", "unknown"),
                        "fixed_version": r_data.get("fixed_version", ""),
                        "urgency": r_data.get("urgency", "")
                    }
            
            git_info = git_infos.get(cve_id, {"upstream_commits": [], "notes": []})
            
            out_data = {
                "cve_id": cve_id,
                "source": "debian",
                "package": self.package,
                "releases": releases,
                "upstream_commits": git_info["upstream_commits"],
                "advisories": [], # Stub, parsed from DSA/list ideally
                "notes": git_info["notes"]
            }
            
            out_file = self.output_dir / f"{cve_id}.json"
            with open(out_file, "w") as out_f:
                json.dump(out_data, out_f, indent=2)
                
            results[cve_id] = out_file
            
        logger.info(f"Processed {len(results)} Debian CVE records.")
        return results

if __name__ == '__main__':
    import yaml
    config_path = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\config.yaml")
    config = {}
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
            
    out_dir = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\data\raw\debian")
    collector = DebianCollector(config, out_dir)
    collector.collect()
