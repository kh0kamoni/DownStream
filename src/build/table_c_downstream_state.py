import json
import logging
import pandas as pd
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TableCBuilder:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.raw_dir = self.project_root / "data" / "raw"
        self.pilot_dir = self.project_root / "data" / "pilot"
        self.pilot_dir.mkdir(parents=True, exist_ok=True)
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

    def get_security_state(self, tracker_status: str, has_upstream_ref: bool, notes: str) -> str:
        if tracker_status in ['not-affected', 'DNE']:
            return 'D0_not_affected'
        elif tracker_status in ['open', 'needed', 'unfixed', 'needs-triage', 'deferred']:
            return 'D1_vulnerable'
        elif tracker_status in ['resolved', 'released', 'fixed']:
            if has_upstream_ref:
                return 'D2_fixed_equivalent'
            else:
                return 'D3_modified_fix'
        elif tracker_status in ['no-dsa', 'postponed']:
            return 'D4_partial_fix'
        elif tracker_status in ['ignored'] and 'not applicable' in notes.lower():
            return 'D5_config_unreachable'
        else:
            return 'D6_uncertain'

    def get_binary_state(self, state: str) -> str:
        if state in ['D1_vulnerable', 'D4_partial_fix']:
            return 'EXPOSED'
        elif state in ['D0_not_affected', 'D2_fixed_equivalent', 'D3_modified_fix', 'D5_config_unreachable']:
            return 'NOT_EXPOSED'
        return 'UNCERTAIN'

    def _process_cve(self, cve: str, up_commit: str) -> List[Dict[str, Any]]:
        deb_data = self._read_json(self.debian_dir / f"{cve}.json")
        ub_data = self._read_json(self.ubuntu_dir / f"{cve}.json")
        
        cve_rows = []
        
        # 1. Debian releases
        deb_text = json.dumps(deb_data) if up_commit else ""
        for rel, info in deb_data.get("releases", {}).items():
            status = info.get("status", "unknown")
            fixed_ver = info.get("fixed_version", "")
            urgency = info.get("urgency", "unknown")
            notes = info.get("notes", "")
            advisories = info.get("advisories", [])
            
            has_ref = bool(up_commit and up_commit in deb_text)
            sec_state = self.get_security_state(status, has_ref, notes)
            
            cve_rows.append({
                'cve_id': cve,
                'downstream': 'debian',
                'downstream_version': rel,
                'package': 'linux',
                'tracker_status': status,
                'fixed_version': fixed_ver,
                'urgency': urgency,
                'upstream_commit': up_commit,
                'has_upstream_commit_ref': has_ref,
                'advisory_ids': ";".join(advisories),
                'security_state': sec_state,
                'security_state_binary': self.get_binary_state(sec_state),
                'version_distance_proxy': 0.0
            })
            
        # 2. Ubuntu releases
        ub_text = json.dumps(ub_data) if up_commit else ""
        for rel, info in ub_data.get("releases", {}).items():
            status = info.get("status", "unknown")
            fixed_ver = info.get("fixed_version", "")
            priority = info.get("priority", "unknown")
            notes = info.get("notes", "")
            advisories = info.get("notices", [])
            
            has_ref = bool(up_commit and up_commit in ub_text)
            sec_state = self.get_security_state(status, has_ref, notes)
            
            cve_rows.append({
                'cve_id': cve,
                'downstream': 'ubuntu',
                'downstream_version': rel,
                'package': 'linux',
                'tracker_status': status,
                'fixed_version': fixed_ver,
                'urgency': priority,
                'upstream_commit': up_commit,
                'has_upstream_commit_ref': has_ref,
                'advisory_ids': ";".join(advisories),
                'security_state': sec_state,
                'security_state_binary': self.get_binary_state(sec_state),
                'version_distance_proxy': 0.0
            })
            
        return cve_rows

    def build(self) -> None:
        selected_path = self.pilot_dir / "selected_cves.json"
        if not selected_path.exists():
            logging.error("selected_cves.json not found.")
            return
            
        with open(selected_path, 'r', encoding='utf-8') as f:
            selected_cves = json.load(f).get("selected", [])
            
        tb_path = self.pilot_dir / "table_b_upstream_patch.parquet"
        upstream_commits = {}
        if tb_path.exists():
            df_b = pd.read_parquet(tb_path)
            upstream_commits = dict(zip(df_b.cve_id, df_b.upstream_commit))
            
        logging.info(f"Building Table C for {len(selected_cves)} CVEs with 16 parallel workers...")
        with ThreadPoolExecutor(max_workers=16) as pool:
            nested_rows = list(pool.map(lambda c: self._process_cve(c, upstream_commits.get(c, "")), selected_cves))
            
        flat_rows = [row for sublist in nested_rows for row in sublist]
        df = pd.DataFrame(flat_rows)
        parquet_path = self.pilot_dir / "table_c_downstream_state.parquet"
        csv_path = self.pilot_dir / "table_c_downstream_state.csv"
        
        df.to_parquet(parquet_path, index=False)
        df.to_csv(csv_path, index=False)
        logging.info(f"Successfully saved full-scale Table C ({len(df)} downstream records) to {parquet_path} and {csv_path}")

if __name__ == "__main__":
    builder = TableCBuilder(r"c:\Users\Khoka Moni\Downloads\research_all\downstream")
    builder.build()
