import json
import logging
from pathlib import Path
from typing import Dict
from tqdm import tqdm
import glob
import tempfile
import shutil

try:
    from src.utils.parsers import parse_vulns_git_json, parse_vulns_git_mbox
    from src.utils.git_utils import clone_or_pull
except ImportError:
    def parse_vulns_git_json(f): return {}
    def parse_vulns_git_mbox(f): return {}
    def clone_or_pull(repo, dst, shallow=True): pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class KernelVulnsCollector:
    def __init__(self, config: dict, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.years = self.config.get("years", [2022, 2023, 2024, 2025])
        self.repo_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git/"
        self.repo_dir = self.output_dir.parent / "vulns_git_repo"

    def collect(self) -> Dict[str, Path]:
        logger.info(f"Cloning/Pulling kernel vulns repo to {self.repo_dir}")
        clone_or_pull(self.repo_url, self.repo_dir, shallow=False)
        
        results = {}
        for year in self.years:
            year_dir = self.repo_dir / "cve" / "published" / str(year)
            if not year_dir.exists():
                continue
                
            json_files = glob.glob(str(year_dir / "CVE-*.json"))
            
            logger.info(f"Processing {len(json_files)} kernel vulns for year {year}")
            for jf in tqdm(json_files, desc=f"Year {year}"):
                cve_id = Path(jf).stem
                
                with open(jf, "r", encoding="utf-8") as f:
                    data = parse_vulns_git_json(json.load(f))
                    
                # Default mapping assuming parser normalized fields
                out_data = {
                    "cve_id": cve_id,
                    "source": "kernel_vulns",
                    "description": data.get("description", ""),
                    "introducing_commits": data.get("introducing_commits", []),
                    "fixing_commits": data.get("fixing_commits", []),
                    "affected_versions": data.get("affected_versions", []),
                    "affected_files": data.get("affected_files", []),
                    "reference_urls": data.get("reference_urls", []),
                    "cna_state": data.get("cna_state", "PUBLISHED")
                }
                
                out_file = self.output_dir / f"{cve_id}.json"
                with open(out_file, "w") as out_f:
                    json.dump(out_data, out_f, indent=2)
                    
                results[cve_id] = out_file
                
        logger.info(f"Processed {len(results)} total kernel CVEs.")
        return results

if __name__ == '__main__':
    import yaml
    config_path = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\config.yaml")
    config = {}
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
            
    out_dir = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\data\raw\kernel_vulns")
    collector = KernelVulnsCollector(config, out_dir)
    collector.collect()
