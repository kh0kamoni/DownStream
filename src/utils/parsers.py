"""
parsers.py - Parsers for all data source formats for DownstreamSec project.
"""
import json
import logging
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def extract_git_urls(text: str) -> List[str]:
    """
    Extract all git.kernel.org/github commit URLs from arbitrary text using regex.
    Returns a list of extracted commit SHAs (not URLs).
    """
    patterns = [
        r'https://git\.kernel\.org/stable/c/([0-9a-f]{40})',
        r'https://git\.kernel\.org/linus/([0-9a-f]{12,40})',
        r'https://git\.kernel\.org/pub/scm/[^\s]+/commit/\?id=([0-9a-f]{12,40})',
        r'https://github\.com/torvalds/linux/commit/([0-9a-f]{12,40})'
    ]
    shas = []
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            shas.append(match.group(1))
    # Deduplicate while preserving order
    seen = set()
    return [x for x in shas if not (x in seen or seen.add(x))]

def parse_vulns_git_json(filepath: Union[Path, str, Dict[str, Any]]) -> Dict[str, Any]:
    """Parse a CVE JSON 5.0 record from kernel vulns.git."""
    if isinstance(filepath, dict):
        data = filepath
    else:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return {}

    result = {
        'cve_id': '',
        'description': '',
        'introducing_commits': [],
        'fixing_commits': [],
        'version_ranges': [],
        'affected_files': [],
        'reference_urls': [],
        'stable_backport_shas': []
    }

    cve_metadata = data.get('cveMetadata', {})
    result['cve_id'] = cve_metadata.get('cveId', '')

    containers = data.get('containers', {})
    cna = containers.get('cna', {})
    
    descriptions = cna.get('descriptions', [])
    if descriptions:
        result['description'] = descriptions[0].get('value', '')

    affected = cna.get('affected', [])
    for aff in affected:
        versions = aff.get('versions', [])
        for ver in versions:
            v_type = ver.get('versionType', '')
            if v_type == 'git':
                if 'version' in ver and ver['version'] not in ('unspecified', '*'):
                    result['introducing_commits'].append({
                        'sha': ver['version'],
                        'branch': ''  # Branch info might not be explicit in the version string
                    })
                if 'lessThan' in ver and ver['lessThan'] not in ('unspecified', '*'):
                    result['fixing_commits'].append({
                        'sha': ver['lessThan'],
                        'branch': ''
                    })
            elif v_type == 'custom':
                if 'version' in ver and 'lessThan' in ver:
                    result['version_ranges'].append({
                        'start': ver['version'],
                        'end': ver['lessThan']
                    })
        
        program_files = aff.get('programFiles', [])
        result['affected_files'].extend(program_files)

    references = cna.get('references', [])
    for ref in references:
        url = ref.get('url', '')
        if url:
            result['reference_urls'].append(url)
            shas = extract_git_urls(url)
            for sha in shas:
                # Typically stable backports are git.kernel.org/stable/c/
                if 'stable/c/' in url:
                    result['stable_backport_shas'].append(sha)

    # Deduplicate
    result['affected_files'] = list(set(result['affected_files']))
    result['reference_urls'] = list(set(result['reference_urls']))
    result['stable_backport_shas'] = list(set(result['stable_backport_shas']))

    return result

def parse_vulns_git_mbox(filepath: Path) -> Dict[str, Any]:
    """Parse .mbox advisory file from vulns.git as fallback."""
    result = {
        'cve_id': '',
        'description': '',
        'fixing_commits': [],
        'affected_versions': []
    }
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        subj_match = re.search(r'^Subject:\s*(.*?CVE-\d{4}-\d+.*)$', content, re.MULTILINE)
        if subj_match:
            cve_match = re.search(r'(CVE-\d{4}-\d+)', subj_match.group(1))
            if cve_match:
                result['cve_id'] = cve_match.group(1)
        
        # Simple extraction for description, fixing commits, affected versions based on common patterns
        fixed_by_match = re.search(r'Fixed by commits?:\s*((?:[0-9a-f]+\s*)+)', content, re.IGNORECASE)
        if fixed_by_match:
            shas = re.findall(r'[0-9a-f]{12,40}', fixed_by_match.group(1))
            result['fixing_commits'] = shas
            
        affected_match = re.search(r'Affected versions?:\s*(.*)', content, re.IGNORECASE)
        if affected_match:
            result['affected_versions'].append(affected_match.group(1).strip())
            
        # Extrapolate description from the body (simplified)
        body = content.split('\n\n', 1)
        if len(body) > 1:
            result['description'] = body[1].strip()[:200] # just taking a snippet
            
    except Exception as e:
        logger.error(f"Failed to read mbox {filepath}: {e}")
        
    return result

def parse_debian_cve_list_entry(text_block: str) -> Dict[str, Any]:
    """Parse a single CVE entry from Debian's data/CVE/list flat-text format."""
    lines = text_block.strip().split('\n')
    result = {
        'cve_id': '',
        'description': '',
        'releases': [],
        'notes': [],
        'advisory_references': [],
        'git_commit_urls': []
    }
    if not lines:
        return result
        
    header = lines[0].strip()
    cve_match = re.match(r'^(CVE-\d{4}-\d+)\s*\((.*)\)', header)
    if cve_match:
        result['cve_id'] = cve_match.group(1)
        result['description'] = cve_match.group(2)
        
    for line in lines[1:]:
        line = line.strip()
        if line.startswith('{') and line.endswith('}'):
            adv_match = re.findall(r'(DSA-\d+-\d+|DLA-\d+-\d+)', line)
            result['advisory_references'].extend(adv_match)
        elif line.startswith('-'):
            # - package version (status)
            pkg_match = re.match(r'-\s+([^\s]+)\s+([^\s]+)\s*\((.*?)\)', line)
            if pkg_match:
                result['releases'].append({
                    'release': '',
                    'package': pkg_match.group(1),
                    'version': pkg_match.group(2),
                    'status': pkg_match.group(3)
                })
            else:
                # - package <unfixed> (status)
                pkg_match_unfixed = re.match(r'-\s+([^\s]+)\s+<unfixed>\s*\((.*?)\)', line)
                if pkg_match_unfixed:
                    result['releases'].append({
                        'release': '',
                        'package': pkg_match_unfixed.group(1),
                        'version': '<unfixed>',
                        'status': pkg_match_unfixed.group(2)
                    })
        elif line.startswith('['):
            # [release] - package version
            rel_match = re.match(r'\[(.*?)\]\s*-\s+([^\s]+)\s+(.*)', line)
            if rel_match:
                status_match = re.search(r'\((.*?)\)$', rel_match.group(3))
                status = status_match.group(1) if status_match else ''
                version = re.sub(r'\s*\(.*?\)$', '', rel_match.group(3)).strip()
                result['releases'].append({
                    'release': rel_match.group(1),
                    'package': rel_match.group(2),
                    'version': version,
                    'status': status
                })
        elif line.startswith('NOTE:'):
            note = line[5:].strip()
            result['notes'].append(note)
            urls = re.findall(r'https?://[^\s]+', note)
            for url in urls:
                if 'git' in url or 'commit' in url:
                    result['git_commit_urls'].append(url)
                    
    return result

def parse_debian_json_entry(package_name: str, cve_id: str, cve_data: dict) -> Dict[str, Any]:
    """Parse a single CVE entry from Debian's /tracker/data/json endpoint."""
    result = {
        'cve_id': cve_id,
        'package_name': package_name,
        'description': cve_data.get('description', ''),
        'releases': []
    }
    releases = cve_data.get('releases', {})
    for release, data in releases.items():
        result['releases'].append({
            'release': release,
            'status': data.get('status', ''),
            'fixed_version': data.get('fixed_version', ''),
            'urgency': data.get('urgency', ''),
            'repositories': data.get('repositories', {})
        })
    return result

def parse_ubuntu_cve_file(filepath: Path) -> Dict[str, Any]:
    """Parse a single Ubuntu CVE tracker file (RFC 822 / Key: Value format)."""
    result = {
        'cve_id': '',
        'public_date': '',
        'references': [],
        'patches': [],
        'releases': [],
        'priority': '',
        'cvss': '',
        'notes': []
    }
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        current_key = None
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
                
            if not line.startswith(' ') and not line.startswith('\t') and ':' in line:
                key, val = line.split(':', 1)
                current_key = key.strip()
                val = val.strip()
                
                if current_key == 'Candidate':
                    result['cve_id'] = val
                elif current_key == 'PublicDate':
                    result['public_date'] = val
                elif current_key == 'Priority':
                    result['priority'] = val
                elif current_key == 'CVSS':
                    result['cvss'] = val
                elif val and current_key.startswith('Patches_'):
                    result['patches'].append(val)
                elif val and current_key == 'References':
                    result['references'].append(val)
                elif val and current_key.endswith('_linux'): # <package>_<source>:
                    pass
            elif line.startswith(' ') or line.startswith('\t'):
                if current_key == 'References':
                    result['references'].append(line_stripped)
                elif current_key and current_key.startswith('Patches_'):
                    result['patches'].append(line_stripped)
                elif current_key and current_key.endswith('_linux'):
                    # <release>: <status> [(detail)]
                    rel_match = re.match(r'([^\:]+):\s*(.*)', line_stripped)
                    if rel_match:
                        release = rel_match.group(1).strip()
                        status_str = rel_match.group(2).strip()
                        
                        status_parts = status_str.split(' ', 1)
                        status = status_parts[0]
                        detail = status_parts[1].strip('()') if len(status_parts) > 1 else ''
                        
                        result['releases'].append({
                            'package': current_key,
                            'release': release,
                            'status': status,
                            'detail': detail
                        })
                elif current_key == 'Notes':
                    result['notes'].append(line_stripped)
                    
    except Exception as e:
        logger.error(f"Failed to read ubuntu cve {filepath}: {e}")
        
    return result

def parse_osv_entry(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an OSV JSON record."""
    result = {
        'cve_id': data.get('id', ''),
        'introducing_commits': [],
        'fixing_commits': []
    }
    
    aliases = data.get('aliases', [])
    for alias in aliases:
        if alias.startswith('CVE-'):
            result['cve_id'] = alias
            break
            
    affected = data.get('affected', [])
    for aff in affected:
        ranges = aff.get('ranges', [])
        for r in ranges:
            if r.get('type') == 'GIT':
                events = r.get('events', [])
                for event in events:
                    if 'introduced' in event and event['introduced'] != '0':
                        result['introducing_commits'].append(event['introduced'])
                    if 'fixed' in event:
                        result['fixing_commits'].append(event['fixed'])
                        
    result['introducing_commits'] = list(set(result['introducing_commits']))
    result['fixing_commits'] = list(set(result['fixing_commits']))
    
    return result

def normalize_debian_status(status_str: str) -> str:
    """Map Debian's various status strings to a normalized set."""
    status_str = status_str.lower().strip()
    if 'resolved' in status_str or 'fixed' in status_str:
        return 'resolved'
    if 'not-affected' in status_str or 'not affected' in status_str:
        return 'not-affected'
    if 'ignored' in status_str:
        return 'ignored'
    if 'end-of-life' in status_str:
        return 'end-of-life'
    if 'undetermined' in status_str:
        return 'undetermined'
    if 'open' in status_str or 'vulnerable' in status_str:
        return 'open'
    return status_str

def normalize_ubuntu_status(status_str: str) -> str:
    """Map Ubuntu's status strings to normalized set."""
    status_str = status_str.lower().strip()
    if 'released' in status_str:
        return 'released'
    if 'needed' in status_str:
        return 'needed'
    if 'not-affected' in status_str:
        return 'not-affected'
    if 'dne' in status_str:
        return 'DNE'
    if 'ignored' in status_str:
        return 'ignored'
    if 'pending' in status_str:
        return 'pending'
    if 'deferred' in status_str:
        return 'deferred'
    if 'needs-triage' in status_str:
        return 'needs-triage'
    return status_str

if __name__ == "__main__":
    # Simple standalone tests
    print("Testing extract_git_urls")
    text = "Here is a fix: https://git.kernel.org/stable/c/1234567890abcdef1234567890abcdef12345678"
    urls = extract_git_urls(text)
    print(urls)
