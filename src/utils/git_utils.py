"""
git_utils.py - Git operations utility for DownstreamSec project.
"""
import logging
import re
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

import git
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def clone_or_pull(repo_url: str, local_path: Path, shallow: bool = True) -> git.Repo:
    """Clone if not exists, pull if exists."""
    local_path = Path(local_path)
    if local_path.exists() and (local_path / '.git').exists():
        logger.info(f"Repository exists at {local_path}, pulling...")
        try:
            repo = git.Repo(local_path)
            origin = repo.remotes.origin
            origin.pull()
            logger.info("Pull complete.")
            return repo
        except Exception as e:
            logger.error(f"Failed to pull repository at {local_path}: {e}")
            raise
    else:
        logger.info(f"Cloning repository {repo_url} to {local_path}...")
        try:
            kwargs = {}
            if shallow:
                kwargs['depth'] = 1
            repo = git.Repo.clone_from(repo_url, local_path, **kwargs)
            logger.info("Clone complete.")
            return repo
        except Exception as e:
            logger.error(f"Failed to clone repository {repo_url} to {local_path}: {e}")
            raise

def get_commit_metadata(repo: git.Repo, commit_sha: str) -> Optional[Dict[str, Any]]:
    """Get commit info: sha, author, date, message, parents."""
    try:
        commit = repo.commit(commit_sha)
        return {
            'sha': commit.hexsha,
            'author': f"{commit.author.name} <{commit.author.email}>",
            'date': time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime(commit.committed_date)),
            'message': commit.message,
            'parents': [p.hexsha for p in commit.parents]
        }
    except Exception as e:
        logger.error(f"Commit {commit_sha} not found in repo {repo.working_dir}: {e}")
        return None

def get_commit_diff_stats(repo: git.Repo, commit_sha: str) -> Optional[Dict[str, Any]]:
    """Get diff statistics for a commit vs its parent."""
    try:
        commit = repo.commit(commit_sha)
        if not commit.parents:
            parent = git.NULL_TREE
        else:
            parent = commit.parents[0]

        diffs = parent.diff(commit, create_patch=True)
        
        files_changed = []
        functions_changed = []
        loc_added = 0
        loc_deleted = 0
        patch_hunks = 0
        
        for diff in diffs:
            if diff.a_path:
                files_changed.append(diff.a_path)
            elif diff.b_path:
                files_changed.append(diff.b_path)
                
            patch = diff.diff.decode('utf-8', errors='replace')
            for line in patch.split('\n'):
                if line.startswith('@@'):
                    patch_hunks += 1
                    func_match = re.search(r'@@.*@@\s*(.*)', line)
                    if func_match:
                        func_name = func_match.group(1).strip()
                        if func_name:
                            functions_changed.append(func_name)
                elif line.startswith('+') and not line.startswith('+++'):
                    loc_added += 1
                elif line.startswith('-') and not line.startswith('---'):
                    loc_deleted += 1
                    
        return {
            'files_changed': list(set(files_changed)),
            'functions_changed': list(set(functions_changed)),
            'loc_added': loc_added,
            'loc_deleted': loc_deleted,
            'patch_hunks': patch_hunks
        }
    except Exception as e:
        logger.error(f"Diff stats for commit {commit_sha} failed: {e}")
        return None

def get_patch_text(repo: git.Repo, commit_sha: str) -> Optional[str]:
    """Get the full unified diff text for a commit."""
    try:
        return repo.git.show(commit_sha, format="%b")
    except Exception as e:
        logger.error(f"Failed to get patch text for {commit_sha}: {e}")
        return None

def get_commit_date(repo: git.Repo, commit_sha: str) -> Optional[str]:
    """Get ISO format commit date."""
    try:
        commit = repo.commit(commit_sha)
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime(commit.committed_date))
    except Exception as e:
        logger.error(f"Failed to get commit date for {commit_sha}: {e}")
        return None

def extract_fixes_tag(commit_message: str) -> Optional[str]:
    """Extract the SHA from a 'Fixes: <sha> ("...")' tag in a commit message."""
    match = re.search(r'Fixes:\s+([0-9a-f]{8,40})\s+\(', commit_message)
    if match:
        return match.group(1)
    return None

def extract_upstream_commit_tag(commit_message: str) -> Optional[str]:
    """Extract SHA from '[ Upstream commit <sha> ]' or 'commit <sha> upstream.' tags."""
    match1 = re.search(r'\[\s*Upstream commit ([0-9a-f]{12,40})\s*\]', commit_message, re.IGNORECASE)
    if match1:
        return match1.group(1)
        
    match2 = re.search(r'commit ([0-9a-f]{12,40}) upstream', commit_message, re.IGNORECASE)
    if match2:
        return match2.group(1)
        
    return None

def fetch_commit_metadata_github(commit_sha: str, repo_slug: str = 'torvalds/linux') -> Optional[Dict[str, Any]]:
    """Fallback: fetch commit metadata from GitHub API when local clone unavailable."""
    url = f"https://api.github.com/repos/{repo_slug}/commits/{commit_sha}"
    
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'sha': data['sha'],
                    'author': f"{data['commit']['author']['name']} <{data['commit']['author']['email']}>",
                    'date': data['commit']['author']['date'],
                    'message': data['commit']['message'],
                    'parents': [p['sha'] for p in data['parents']]
                }
            elif response.status_code == 403 and 'rate limit' in response.text.lower():
                logger.warning(f"Rate limited by GitHub API. Retrying in 10s (attempt {attempt + 1}/3)")
                time.sleep(10)
            else:
                logger.warning(f"GitHub API returned {response.status_code} for {commit_sha}")
                break
        except requests.exceptions.RequestException as e:
            logger.warning(f"GitHub API request failed: {e}. Retrying in 5s (attempt {attempt + 1}/3)")
            time.sleep(5)
            
    return None

if __name__ == "__main__":
    # Standalone test
    msg = '''
    Some fix
    Fixes: 1234567890ab ("bad commit")
    [ Upstream commit fedcba098765 ]
    '''
    print("Fixes:", extract_fixes_tag(msg))
    print("Upstream:", extract_upstream_commit_tag(msg))
