import json
import logging
import zipfile
import io
from pathlib import Path
from typing import Dict
import requests
from tqdm import tqdm

try:
    from src.utils.parsers import parse_osv_entry
except ImportError:
    def parse_osv_entry(d): return d

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OSVCollector:
    def __init__(self, config: dict, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.url = "https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip"
        self.years = [str(y) for y in self.config.get("years", [2022, 2023, 2024, 2025])]

    def collect(self) -> Dict[str, Path]:
        logger.info(f"Downloading OSV bulk zip from {self.url}")
        response = requests.get(self.url, stream=True)
        response.raise_for_status()
        
        results = {}
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            json_files = [f for f in z.namelist() if f.endswith(".json")]
            logger.info(f"Found {len(json_files)} OSV records. Extracting CVEs...")
            
            for filename in tqdm(json_files, desc="Parsing OSV"):
                with z.open(filename) as f:
                    data = json.load(f)
                    
                parsed = parse_osv_entry(data)
                
                # Check aliases for CVE ID if OSV ID itself isn't a CVE
                cve_id = None
                osv_id = parsed.get("id", data.get("id", ""))
                
                if osv_id.startswith("CVE-"):
                    cve_id = osv_id
                else:
                    for alias in parsed.get("aliases", data.get("aliases", [])):
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break
                            
                if not cve_id:
                    continue
                    
                year_part = cve_id.split("-")[1]
                if year_part not in self.years:
                    continue
                    
                out_data = {
                    "cve_id": cve_id,
                    "source": "osv",
                    "osv_id": osv_id,
                    "aliases": parsed.get("aliases", data.get("aliases", [])),
                    "summary": parsed.get("summary", data.get("summary", "")),
                    "fixing_commits": parsed.get("fixing_commits", []),
                    "introducing_commits": parsed.get("introducing_commits", []),
                    "affected_ranges": parsed.get("affected_ranges", data.get("affected", []))
                }
                
                out_file = self.output_dir / f"{cve_id}.json"
                with open(out_file, "w") as out_f:
                    json.dump(out_data, out_f, indent=2)
                    
                results[cve_id] = out_file

        logger.info(f"Processed {len(results)} OSV CVE records.")
        return results

if __name__ == '__main__':
    import yaml
    config_path = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\config.yaml")
    config = {}
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
            
    out_dir = Path(r"c:\Users\Khoka Moni\Downloads\research_all\downstream\data\raw\osv")
    collector = OSVCollector(config, out_dir)
    collector.collect()
