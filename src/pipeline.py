import argparse
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml
import importlib

# Define the pipeline steps
STEPS = [
    ('ingest_nvd', 'Ingest NVD data'),
    ('ingest_kernel_vulns', 'Ingest kernel vulns.git'),
    ('ingest_osv', 'Ingest OSV bulk export'),
    ('ingest_debian', 'Ingest Debian tracker'),
    ('ingest_ubuntu', 'Ingest Ubuntu tracker'),
    ('select', 'Select 100 CVEs'),
    ('build_table_a', 'Build vulnerability table'),
    ('build_table_b', 'Build upstream patch table'),
    ('build_table_c', 'Build downstream state table'),
    ('build_table_d', 'Build temporal events table'),
    ('evaluate', 'Generate coverage report'),
]

# Mapping step names to module paths, class names, and method to call
STEP_MODULES = {
    'ingest_nvd': ('src.ingest.nvd_collector', 'NVDCollector', 'collect'),
    'ingest_kernel_vulns': ('src.ingest.kernel_vulns_collector', 'KernelVulnsCollector', 'collect'),
    'ingest_osv': ('src.ingest.osv_collector', 'OSVCollector', 'collect'),
    'ingest_debian': ('src.ingest.debian_collector', 'DebianCollector', 'collect'),
    'ingest_ubuntu': ('src.ingest.ubuntu_collector', 'UbuntuCollector', 'collect'),
    'select': ('src.select.cve_selector', 'CVESelector', 'select'),
    'build_table_a': ('src.build.table_a_vulnerability', 'TableABuilder', 'build'),
    'build_table_b': ('src.build.table_b_upstream_patch', 'TableBBuilder', 'build'),
    'build_table_c': ('src.build.table_c_downstream_state', 'TableCBuilder', 'build'),
    'build_table_d': ('src.build.table_d_temporal_events', 'TableDBuilder', 'build'),
    'evaluate': ('src.evaluate.coverage_report', 'CoverageReporter', 'generate'),
}

class DownstreamSecPipeline:
    """Main orchestrator that runs the full pilot pipeline."""
    
    def __init__(self, config_path: str, dry_run: bool = False, force: bool = False):
        self.config_path = Path(config_path)
        self.dry_run = dry_run
        self.force = force
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)
            
        self.project_root = self.config_path.parent
        self.pilot_dir = self.project_root / 'data' / 'pilot'
        self.log_file = self.pilot_dir / 'pipeline.log'
        self.state_file = self.pilot_dir / 'pipeline_state.json'
        
        self._setup_directories()
        self._setup_logging()
        self.state = self._load_state()

    def _setup_directories(self) -> None:
        """Create all necessary directories before running."""
        dirs = [
            self.pilot_dir,
            self.project_root / 'data' / 'raw' / 'nvd',
            self.project_root / 'data' / 'raw' / 'kernel_vulns',
            self.project_root / 'data' / 'raw' / 'osv',
            self.project_root / 'data' / 'raw' / 'debian',
            self.project_root / 'data' / 'raw' / 'ubuntu',
            self.project_root / 'data' / 'processed',
        ]
        if not self.dry_run:
            for d in dirs:
                d.mkdir(parents=True, exist_ok=True)

    def _setup_logging(self) -> None:
        """Set up logging to both console and file."""
        self.logger = logging.getLogger('DownstreamSecPipeline')
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        if not self.dry_run:
            fh = logging.FileHandler(self.log_file, encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def _load_state(self) -> Dict[str, Any]:
        """Load the pipeline state from JSON."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                self.logger.warning("Failed to decode state file, starting fresh.")
        return {}

    def _save_state(self) -> None:
        """Save the pipeline state to JSON."""
        if self.dry_run:
            return
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=4)

    def _run_step(self, step_name: str, step_desc: str) -> None:
        """Run a single step."""
        if step_name in self.state and self.state[step_name].get('status') == 'success' and not self.force:
            self.logger.info(f"Skipping completed step: {step_name} ({step_desc})")
            return

        self.logger.info(f"Starting step: {step_name} - {step_desc}")
        
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would execute {step_name}")
            return

        start_time = time.time()
        start_time_str = datetime.now().isoformat()
        
        try:
            if step_name not in STEP_MODULES:
                raise ValueError(f"Unknown step {step_name}")
                
            module_name, class_name, method_name = STEP_MODULES[step_name]
            module = importlib.import_module(module_name)
            step_class = getattr(module, class_name)
            
            # Instantiate class with appropriate constructor arguments
            project_root_str = str(self.project_root)
            if step_name.startswith('ingest_'):
                # Collectors: __init__(config: dict, output_dir: Path)
                source_name = step_name.replace('ingest_', '')
                output_dir = self.project_root / 'data' / 'raw' / source_name
                output_dir.mkdir(parents=True, exist_ok=True)
                step_instance = step_class(self.config, output_dir)
            elif step_name == 'evaluate':
                # Coverage reporter: __init__(config_path: str)
                step_instance = step_class(str(self.config_path))
            else:
                # Builders and selector: __init__(project_root: str)
                step_instance = step_class(project_root_str)
            
            method = getattr(step_instance, method_name)
            method()
            
            status = 'success'
            end_time = time.time()
            duration = end_time - start_time
            self.logger.info(f"Completed step {step_name} in {duration:.2f} seconds.")
            
        except Exception as e:
            status = 'failed'
            end_time = time.time()
            duration = end_time - start_time
            self.logger.error(f"Failed step {step_name} after {duration:.2f}s: {str(e)}", exc_info=True)
            
        self.state[step_name] = {
            'description': step_desc,
            'status': status,
            'start_time': start_time_str,
            'end_time': datetime.now().isoformat(),
            'duration_seconds': duration
        }
        self._save_state()
        
        if status == 'failed':
            self.logger.error(f"Pipeline halting due to failure in step: {step_name}")
            raise RuntimeError(f"Step {step_name} failed.")

    def run(self, target_step: Optional[str] = None, from_step: Optional[str] = None) -> None:
        """Execute the pipeline steps."""
        self.logger.info(f"Starting pipeline execution. Config: {self.config_path}")
        
        step_names = [s[0] for s in STEPS]
        
        if target_step:
            if target_step not in step_names:
                raise ValueError(f"Invalid target step: {target_step}")
            steps_to_run = [s for s in STEPS if s[0] == target_step]
        elif from_step:
            if from_step not in step_names:
                raise ValueError(f"Invalid from-step: {from_step}")
            start_idx = step_names.index(from_step)
            steps_to_run = STEPS[start_idx:]
        else:
            steps_to_run = STEPS

        for step_name, step_desc in steps_to_run:
            self._run_step(step_name, step_desc)

        self.logger.info("Pipeline execution complete.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DownstreamSec Pipeline Orchestrator')
    parser.add_argument('--config', required=True, help='Path to config.yaml')
    parser.add_argument('--step', help='Run a single specific step')
    parser.add_argument('--from-step', help='Resume from this step (skip prior completed steps)')
    parser.add_argument('--dry-run', action='store_true', help='Print what would be done without executing')
    parser.add_argument('--force', action='store_true', help='Re-run steps even if already completed')
    args = parser.parse_args()

    try:
        pipeline = DownstreamSecPipeline(config_path=args.config, dry_run=args.dry_run, force=args.force)
        pipeline.run(target_step=args.step, from_step=args.from_step)
    except Exception as e:
        print(f"Pipeline failed: {e}")
        exit(1)
