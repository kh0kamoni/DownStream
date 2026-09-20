import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CVESelector:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.config_path = self.project_root / "config.yaml"
        self.raw_dir = self.project_root / "data" / "raw"
        self.pilot_dir = self.project_root / "data" / "pilot"
        self.pilot_dir.mkdir(parents=True, exist_ok=True)
        
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {}
            
        self.target_count = self.config.get("pilot", {}).get("target_cve_count", 9208)
        self.nvd_dir = self.raw_dir / "nvd"
        self.kernel_vulns_dir = self.raw_dir / "kernel_vulns"
        self.debian_dir = self.raw_dir / "debian"
        self.ubuntu_dir = self.raw_dir / "ubuntu"

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _eval_cve(self, cve: str) -> Optional[dict]:
        nvd_data = self._read_json(self.nvd_dir / f"{cve}.json")
        kv_data = self._read_json(self.kernel_vulns_dir / f"{cve}.json")
        debian_data = self._read_json(self.debian_dir / f"{cve}.json")
        ubuntu_data = self._read_json(self.ubuntu_dir / f"{cve}.json")
        
        # Upstream fixing commit identified
        has_upstream = bool(
            kv_data.get("fixing_commits") or
            kv_data.get("fixes") or
            debian_data.get("upstream_commits") or
            ubuntu_data.get("upstream_patches")
        )
        deb_releases = len(debian_data.get("releases", {}))
        ub_releases = len(ubuntu_data.get("releases", {}))
        
        # CVSS & CWE metrics
        cvss_score = nvd_data.get("cvss3_score")
        has_cvss = cvss_score is not None or bool(nvd_data.get("cvss") or nvd_data.get("metrics", {}).get("cvssMetricV31"))
        cwe_ids = nvd_data.get("cwe_ids", [])
        has_cwe = bool(cwe_ids or nvd_data.get("weaknesses") or nvd_data.get("cwe"))
        
        # Criteria: must have upstream commit and multi-release downstream presence
        if not has_upstream or deb_releases < 2 or ub_releases < 2:
            return None
            
        score = 0
        if has_upstream:
            score += 3
        score += deb_releases
        score += ub_releases
        if has_cvss:
            score += 1
        if has_cwe:
            score += 1
        
        # Derive CWE type
        cwe_type = "unknown"
        if cwe_ids:
            cwe_type = cwe_ids[0]
        elif nvd_data.get("weaknesses"):
            cwe_type = nvd_data["weaknesses"][0].get("description", [{}])[0].get("value", "unknown")
            
        # Derive CVSS severity bracket
        cvss_level = "UNKNOWN"
        if cvss_score is not None:
            try:
                score_val = float(cvss_score)
                if score_val >= 9.0:
                    cvss_level = "CRITICAL"
                elif score_val >= 7.0:
                    cvss_level = "HIGH"
                elif score_val >= 4.0:
                    cvss_level = "MEDIUM"
                elif score_val > 0.0:
                    cvss_level = "LOW"
            except (ValueError, TypeError):
                pass
        elif nvd_data.get("metrics", {}).get("cvssMetricV31"):
            cvss_level = nvd_data["metrics"]["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            
        return {
            "cve_id": cve,
            "score": score,
            "cwe_type": cwe_type,
            "cvss_level": cvss_level,
            "deb_releases": deb_releases,
            "ub_releases": ub_releases
        }

    def select(self) -> List[str]:
        nvd_cves = {p.stem for p in self.nvd_dir.glob("*.json")} if self.nvd_dir.exists() else set()
        kernel_cves = {p.stem for p in self.kernel_vulns_dir.glob("*.json")} if self.kernel_vulns_dir.exists() else set()
        debian_cves = {p.stem for p in self.debian_dir.glob("*.json")} if self.debian_dir.exists() else set()
        ubuntu_cves = {p.stem for p in self.ubuntu_dir.glob("*.json")} if self.ubuntu_dir.exists() else set()
        
        common_cves = sorted(nvd_cves & kernel_cves & debian_cves & ubuntu_cves)
        logging.info(f"Scanning {len(common_cves)} CVEs common across all 4 ecosystems using multi-threading...")
        
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(tqdm(pool.map(self._eval_cve, common_cves), total=len(common_cves), desc="Evaluating candidate quality"))
            
        candidates = [r for r in results if r is not None]
        logging.info(f"Qualified candidates matching all criteria: {len(candidates)}")
        
        candidates.sort(key=lambda x: x["score"], reverse=True)
        
        target = min(self.target_count, len(candidates))
        selected = candidates[:target]
        selected_cves = [c["cve_id"] for c in selected]
        
        cwes_seen = {c["cwe_type"] for c in selected}
        cvss_seen = {c["cvss_level"] for c in selected}
        
        with open(self.pilot_dir / "selected_cves.json", "w", encoding="utf-8") as f:
            json.dump({"selected": selected_cves, "metadata": selected}, f, indent=2)
            
        stats = {
            "total_common": len(common_cves),
            "qualified": len(candidates),
            "selected_count": len(selected),
            "unique_cwes": len(cwes_seen),
            "unique_cvss": len(cvss_seen)
        }
        with open(self.pilot_dir / "selection_stats.json", "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
            
        logging.info(f"Successfully selected {len(selected_cves)} CVEs for full-scale dataset. Stats: {stats}")
        return selected_cves

if __name__ == "__main__":
    selector = CVESelector(r"c:\Users\Khoka Moni\Downloads\research_all\downstream")
    selector.select()
