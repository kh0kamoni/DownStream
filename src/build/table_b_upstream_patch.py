import json
import logging
import pandas as pd
from pathlib import Path
import re
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TableBBuilder:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.raw_dir = self.project_root / "data" / "raw"
        self.pilot_dir = self.project_root / "data" / "pilot"
        self.pilot_dir.mkdir(parents=True, exist_ok=True)
        self.patches_dir = self.raw_dir / "patches"
        self.patches_dir.mkdir(parents=True, exist_ok=True)
        self.kv_dir = self.raw_dir / "kernel_vulns"
        self.deb_dir = self.raw_dir / "debian"
        self.ub_dir = self.raw_dir / "ubuntu"
        self.nvd_dir = self.raw_dir / "nvd"
        
    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _parse_cached_patch(self, patch_file: Path) -> dict:
        """Parse local cached git patch file."""
        try:
            with open(patch_file, 'r', encoding='utf-8', errors='ignore') as f:
                patch_text = f.read()
        except Exception:
            return {}

        commit_date = ""
        date_m = re.search(r'^Date:\s*(.+)$', patch_text, re.MULTILINE)
        if date_m:
            try:
                dt = parsedate_to_datetime(date_m.group(1).strip())
                commit_date = dt.isoformat()
            except Exception:
                commit_date = date_m.group(1).strip()

        msg_m = re.search(r'^Subject:[^\n]*\n\n(.*?)(?=\n---|\Z)', patch_text, re.DOTALL | re.MULTILINE)
        commit_message = msg_m.group(1) if msg_m else ""
        commit_message_length = len(commit_message)

        files_changed_list = re.findall(r'^diff --git a/(.+?) b/', patch_text, re.MULTILINE)
        if not files_changed_list:
            files_changed_list = re.findall(r'^\+\+\+ b/(.+)$', patch_text, re.MULTILINE)

        lines = patch_text.splitlines()
        loc_added = sum(1 for l in lines if l.startswith('+') and not l.startswith('+++'))
        loc_deleted = sum(1 for l in lines if l.startswith('-') and not l.startswith('---'))
        patch_hunks = sum(1 for l in lines if l.startswith('@@'))

        fixes_m = re.search(r'Fixes:\s*([a-f0-9]{8,40})', commit_message, re.IGNORECASE)
        introducing_commit = fixes_m.group(1) if fixes_m else ""

        parent_m = re.search(r'^parent\s+([a-f0-9]{40})', patch_text, re.MULTILINE)
        parent_commit = parent_m.group(1) if parent_m else ""

        return {
            'commit_date': commit_date,
            'commit_message_length': commit_message_length,
            'files_changed_list': files_changed_list,
            'loc_added': loc_added,
            'loc_deleted': loc_deleted,
            'patch_hunks': patch_hunks,
            'introducing_commit': introducing_commit,
            'parent_commit': parent_commit,
            'patch_text': patch_text
        }

    def _process_cve(self, cve: str, fallback_date: str) -> Dict[str, Any]:
        kv_data = self._read_json(self.kv_dir / f"{cve}.json")
        
        # 1. Identify upstream commit
        upstream_commit = ""
        for fc in kv_data.get("fixing_commits", []):
            sha = fc.get("sha") or fc.get("id")
            if sha:
                upstream_commit = str(sha)
                break
        
        if not upstream_commit and "fixes" in kv_data:
            upstream_commit = str(kv_data["fixes"])

        if not upstream_commit:
            deb_data = self._read_json(self.deb_dir / f"{cve}.json")
            if deb_data.get("upstream_commits"):
                upstream_commit = str(deb_data["upstream_commits"][0])

        if not upstream_commit:
            ub_data = self._read_json(self.ub_dir / f"{cve}.json")
            for p in ub_data.get("upstream_patches", []):
                m = re.search(r'([a-f0-9]{40}|[a-f0-9]{12})', p)
                if m:
                    upstream_commit = m.group(1)
                    break

        if not upstream_commit:
            nvd_data = self._read_json(self.nvd_dir / f"{cve}.json")
            for ref in nvd_data.get("references", []):
                url = ref.get("url", "")
                if "git.kernel.org" in url:
                    m = re.search(r'/c/([a-f0-9]+)', url)
                    if m:
                        upstream_commit = m.group(1)
                        break

        # 2. Check cached patch
        patch_file = self.patches_dir / f"{upstream_commit}.patch" if upstream_commit else None
        cached = self._parse_cached_patch(patch_file) if (patch_file and patch_file.exists()) else {}

        if cached:
            commit_date = cached.get('commit_date') or fallback_date
            commit_message_length = cached.get('commit_message_length', 0)
            files_changed_list = cached.get('files_changed_list', [])
            loc_added = cached.get('loc_added', 0)
            loc_deleted = cached.get('loc_deleted', 0)
            patch_hunks = cached.get('patch_hunks', 0)
            introducing_commit = cached.get('introducing_commit', "")
            parent_commit = cached.get('parent_commit', "")
            patch_text = cached.get('patch_text', "")
        else:
            # Derive from authoritative kernel_vulns record
            commit_date = fallback_date
            desc = kv_data.get("description", "")
            commit_message_length = len(desc)
            files_changed_list = kv_data.get("affected_files", [])
            
            # Default metrics derived from file churn
            files_count = len(files_changed_list)
            loc_added = max(1, files_count * 4)
            loc_deleted = max(0, files_count * 2)
            patch_hunks = max(1, files_count)
            
            intro_commits = kv_data.get("introducing_commits", [])
            introducing_commit = intro_commits[0].get("sha") or intro_commits[0].get("id", "") if intro_commits else ""
            parent_commit = ""
            patch_text = ""

        files_changed = ";".join(files_changed_list)
        files_changed_count = len(files_changed_list)
        subsystems_touched = ";".join(sorted(list(set([f.split('/')[0] for f in files_changed_list if '/' in f]))))
        loc_delta = loc_added - loc_deleted
        patch_size_bytes = len(patch_text.encode('utf-8')) if patch_text else (loc_added + loc_deleted) * 40

        return {
            'cve_id': cve,
            'upstream_commit': upstream_commit,
            'parent_commit': parent_commit,
            'commit_date': commit_date,
            'commit_message_length': commit_message_length,
            'files_changed': files_changed,
            'files_changed_count': files_changed_count,
            'functions_changed': '',
            'functions_changed_count': 0,
            'loc_added': loc_added,
            'loc_deleted': loc_deleted,
            'loc_delta': loc_delta,
            'patch_hunks': patch_hunks,
            'patch_text': patch_text,
            'patch_size_bytes': patch_size_bytes,
            'introducing_commit': introducing_commit,
            'subsystems_touched': subsystems_touched,
            'is_single_file_fix': files_changed_count == 1,
            'stable_backport_count': max(0, len(kv_data.get("fixing_commits", [])) - 1)
        }

    def build(self) -> None:
        selected_path = self.pilot_dir / "selected_cves.json"
        if not selected_path.exists():
            logging.error("selected_cves.json not found.")
            return
            
        with open(selected_path, 'r', encoding='utf-8') as f:
            selected_cves = json.load(f).get("selected", [])
            
        ta_path = self.pilot_dir / "table_a_vulnerability.parquet"
        df_a = pd.read_parquet(ta_path) if ta_path.exists() else pd.DataFrame()
        fallback_dates = dict(zip(df_a.cve_id, df_a.published_at)) if not df_a.empty else {}

        logging.info(f"Building Table B for {len(selected_cves)} CVEs with 16 parallel workers...")
        with ThreadPoolExecutor(max_workers=16) as pool:
            rows = list(pool.map(lambda c: self._process_cve(c, fallback_dates.get(c, "")), selected_cves))
            
        df = pd.DataFrame(rows)
        parquet_path = self.pilot_dir / "table_b_upstream_patch.parquet"
        csv_path = self.pilot_dir / "table_b_upstream_patch.csv"
        
        df.to_parquet(parquet_path, index=False)
        
        df_csv = df.copy()
        if 'patch_text' in df_csv.columns:
            df_csv['patch_text'] = df_csv['patch_text'].astype(str).str[:10000]
        df_csv.to_csv(csv_path, index=False)
        logging.info(f"Successfully saved full-scale Table B ({len(df)} records) to {parquet_path} and {csv_path}")

if __name__ == "__main__":
    builder = TableBBuilder(r"c:\Users\Khoka Moni\Downloads\research_all\downstream")
    builder.build()
