import json
import logging
import pandas as pd
from pathlib import Path
from datetime import datetime
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TableDBuilder:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.raw_dir = self.project_root / "data" / "raw"
        self.pilot_dir = self.project_root / "data" / "pilot"
        self.pilot_dir.mkdir(parents=True, exist_ok=True)
        self.debian_dir = self.raw_dir / "debian"
        self.ubuntu_dir = self.raw_dir / "ubuntu"
        self.kv_dir = self.raw_dir / "kernel_vulns"
        self.nvd_dir = self.raw_dir / "nvd"
        self.usn_dir = self.raw_dir / "usn"
        self.ub_osv_dir = self.raw_dir / "ubuntu_osv"

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _parse_date(self, date_str: str):
        if not date_str:
            return None
        # Handle formats like "19 Sep 2026"
        try:
            return datetime.strptime(date_str.strip(), '%d %b %Y')
        except Exception:
            pass
        # Handle ISO strings
        try:
            clean_str = date_str.replace('Z', '+00:00')
            dt = datetime.fromisoformat(clean_str)
            return dt.replace(tzinfo=None)
        except Exception:
            return None

    def _load_dsa_map(self) -> dict:
        dsa_map = {}
        for p in [
            self.raw_dir / "debian_git" / "data" / "DSA" / "list",
            self.raw_dir / "debian_git" / "data" / "DLA" / "list"
        ]:
            if not p.exists():
                continue
            curr_date = None
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = re.match(r'^\[(\d{1,2}\s+[A-Za-z]{3}\s+\d{4})\]', line)
                    if m:
                        curr_date = m.group(1)
                    for cve in re.findall(r'CVE-\d{4}-\d+', line):
                        if cve not in dsa_map and curr_date:
                            dsa_map[cve] = curr_date
        return dsa_map

    def _process_cve(
        self,
        cve: str,
        disclosure_date: str,
        upstream_date: str,
        upstream_commit: str,
        deb_ver_dates: dict,
        dsa_map: dict
    ) -> List[Dict[str, Any]]:
        cve_rows = []
        d_dt = self._parse_date(disclosure_date)
        u_dt = self._parse_date(upstream_date)
        
        nvd_data = self._read_json(self.nvd_dir / f"{cve}.json")
        nvd_mod = nvd_data.get("last_modified") or nvd_data.get("published")
        
        # 1. DISCLOSURE
        cve_rows.append({
            'cve_id': cve,
            'downstream': 'upstream',
            'downstream_version': 'mainline',
            'event_type': 'DISCLOSURE',
            'event_timestamp': disclosure_date,
            'commit': None,
            'version': None,
            'days_since_disclosure': 0.0,
            'days_since_upstream_fix': None,
            'remediation_latency_days': None
        })
        
        # 2. UPSTREAM_FIX
        if upstream_date:
            days_since_disc = (u_dt - d_dt).total_seconds() / 86400.0 if u_dt and d_dt else None
            cve_rows.append({
                'cve_id': cve,
                'downstream': 'upstream',
                'downstream_version': 'mainline',
                'event_type': 'UPSTREAM_FIX',
                'event_timestamp': upstream_date,
                'commit': upstream_commit,
                'version': None,
                'days_since_disclosure': round(days_since_disc, 2) if days_since_disc is not None else None,
                'days_since_upstream_fix': 0.0,
                'remediation_latency_days': None
            })
            
        # 3. BACKPORTS
        kv_data = self._read_json(self.kv_dir / f"{cve}.json")
        for bc in kv_data.get("fixing_commits", [])[1:]:
            cve_rows.append({
                'cve_id': cve,
                'downstream': 'upstream',
                'downstream_version': 'stable',
                'event_type': 'BACKPORT',
                'event_timestamp': None,
                'commit': bc.get("sha") or bc.get("id"),
                'version': None,
                'days_since_disclosure': None,
                'days_since_upstream_fix': None,
                'remediation_latency_days': None
            })
            
        # 4. Debian downstream
        deb_data = self._read_json(self.debian_dir / f"{cve}.json")
        for rel, info in deb_data.get("releases", {}).items():
            st = info.get("status")
            fixed_ver = info.get("fixed_version", "")
            
            if st in ["resolved", "released", "fixed"]:
                event_ts = dsa_map.get(cve) or deb_ver_dates.get(fixed_ver) or nvd_mod
                e_dt = self._parse_date(event_ts)
                
                days_since_disc = (e_dt - d_dt).total_seconds() / 86400.0 if e_dt and d_dt else None
                days_since_up = (e_dt - u_dt).total_seconds() / 86400.0 if e_dt and u_dt else None
                latency = days_since_up if days_since_up is not None else days_since_disc
                if latency is not None:
                    latency = max(0.0, round(latency, 2))
                    
                cve_rows.append({
                    'cve_id': cve,
                    'downstream': 'debian',
                    'downstream_version': rel,
                    'event_type': 'DOWNSTREAM_FIX',
                    'event_timestamp': event_ts,
                    'commit': None,
                    'version': fixed_ver,
                    'days_since_disclosure': round(days_since_disc, 2) if days_since_disc is not None else None,
                    'days_since_upstream_fix': round(days_since_up, 2) if days_since_up is not None else None,
                    'remediation_latency_days': latency
                })
            elif st in ["not-affected", "DNE"]:
                cve_rows.append({
                    'cve_id': cve,
                    'downstream': 'debian',
                    'downstream_version': rel,
                    'event_type': 'DOWNSTREAM_NOT_AFFECTED',
                    'event_timestamp': upstream_date or disclosure_date,
                    'commit': None,
                    'version': None,
                    'days_since_disclosure': 0.0,
                    'days_since_upstream_fix': 0.0,
                    'remediation_latency_days': 0.0
                })
                
        # 5. Ubuntu downstream
        ub_data = self._read_json(self.ubuntu_dir / f"{cve}.json")
        for rel, info in ub_data.get("releases", {}).items():
            st = info.get("status")
            fixed_ver = info.get("fixed_version", "")
            
            if st in ["resolved", "released", "fixed"]:
                u_date = None
                for usn in ub_data.get("notices", []):
                    usn_file = self.usn_dir / f"{usn}.json"
                    if usn_file.exists():
                        usn_data = self._read_json(usn_file)
                        if usn_data.get("published"):
                            u_date = usn_data["published"]
                            break
                if not u_date:
                    ub_osv_file = self.ub_osv_dir / f"{cve}.json"
                    if ub_osv_file.exists():
                        ub_osv = self._read_json(ub_osv_file)
                        u_date = ub_osv.get("published") or ub_osv.get("modified")
                if not u_date:
                    u_date = nvd_mod
                    
                event_ts = u_date
                e_dt = self._parse_date(event_ts)
                
                days_since_disc = (e_dt - d_dt).total_seconds() / 86400.0 if e_dt and d_dt else None
                days_since_up = (e_dt - u_dt).total_seconds() / 86400.0 if e_dt and u_dt else None
                latency = days_since_up if days_since_up is not None else days_since_disc
                if latency is not None:
                    latency = max(0.0, round(latency, 2))
                    
                cve_rows.append({
                    'cve_id': cve,
                    'downstream': 'ubuntu',
                    'downstream_version': rel,
                    'event_type': 'DOWNSTREAM_FIX',
                    'event_timestamp': event_ts,
                    'commit': None,
                    'version': fixed_ver,
                    'days_since_disclosure': round(days_since_disc, 2) if days_since_disc is not None else None,
                    'days_since_upstream_fix': round(days_since_up, 2) if days_since_up is not None else None,
                    'remediation_latency_days': latency
                })
            elif st in ["not-affected", "DNE"]:
                cve_rows.append({
                    'cve_id': cve,
                    'downstream': 'ubuntu',
                    'downstream_version': rel,
                    'event_type': 'DOWNSTREAM_NOT_AFFECTED',
                    'event_timestamp': upstream_date or disclosure_date,
                    'commit': None,
                    'version': None,
                    'days_since_disclosure': 0.0,
                    'days_since_upstream_fix': 0.0,
                    'remediation_latency_days': 0.0
                })
                
        return cve_rows

    def build(self) -> None:
        selected_path = self.pilot_dir / "selected_cves.json"
        if not selected_path.exists():
            logging.error("selected_cves.json not found.")
            return
            
        with open(selected_path, 'r', encoding='utf-8') as f:
            selected_cves = json.load(f).get("selected", [])
            
        ta_path = self.pilot_dir / "table_a_vulnerability.parquet"
        tb_path = self.pilot_dir / "table_b_upstream_patch.parquet"
        
        df_a = pd.read_parquet(ta_path) if ta_path.exists() else pd.DataFrame()
        df_b = pd.read_parquet(tb_path) if tb_path.exists() else pd.DataFrame()
        
        pub_dates = dict(zip(df_a.cve_id, df_a.published_at)) if not df_a.empty else {}
        up_dates = dict(zip(df_b.cve_id, df_b.commit_date)) if not df_b.empty else {}
        up_commits = dict(zip(df_b.cve_id, df_b.upstream_commit)) if not df_b.empty else {}
        
        deb_ver_file = self.raw_dir / "debian_version_dates.json"
        deb_ver_dates = self._read_json(deb_ver_file)
        dsa_map = self._load_dsa_map()
        
        logging.info(f"Building Table D for {len(selected_cves)} CVEs with 16 parallel workers...")
        with ThreadPoolExecutor(max_workers=16) as pool:
            nested_rows = list(pool.map(
                lambda c: self._process_cve(
                    c,
                    pub_dates.get(c, ""),
                    up_dates.get(c, ""),
                    up_commits.get(c, ""),
                    deb_ver_dates,
                    dsa_map
                ),
                selected_cves
            ))
            
        flat_rows = [row for sublist in nested_rows for row in sublist]
        df = pd.DataFrame(flat_rows)
        parquet_path = self.pilot_dir / "table_d_temporal_events.parquet"
        csv_path = self.pilot_dir / "table_d_temporal_events.csv"
        
        df.to_parquet(parquet_path, index=False)
        df.to_csv(csv_path, index=False)
        logging.info(f"Successfully saved full-scale Table D ({len(df)} temporal events) to {parquet_path} and {csv_path}")

if __name__ == "__main__":
    builder = TableDBuilder(r"c:\Users\Khoka Moni\Downloads\research_all\downstream")
    builder.build()
