"""Git repository utilities for managing project git information"""
import os
import subprocess
import logging
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


def is_git_repository(path: str) -> bool:
    """
    Check if the given path is a git repository.
    
    Args:
        path: Path to check
        
    Returns:
        True if path is a git repository, False otherwise
    """
    if not path or not os.path.exists(path):
        return False
    
    git_dir = os.path.join(path, '.git')
    return os.path.isdir(git_dir)


def get_git_info(repo_path: str) -> Optional[Dict[str, any]]:
    """
    Get git repository information including current branch, latest commit, etc.
    
    Args:
        repo_path: Path to the git repository
        
    Returns:
        Dictionary with git info or None if not a git repo or error occurs
        {
            'current_branch': str,
            'commit_hash': str,
            'commit_hash_short': str,
            'commit_message': str,
            'commit_author': str,
            'commit_date': str,
            'remote_url': str,
            'is_dirty': bool,  # Has uncommitted changes
            'branches': List[str]  # List of all local branches
        }
    """
    if not is_git_repository(repo_path):
        return None
    
    try:
        git_info = {}
        
        # Get current branch
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['current_branch'] = result.stdout.strip()
            else:
                git_info['current_branch'] = 'unknown'
        except Exception as e:
            logger.warning(f"Error getting current branch: {e}")
            git_info['current_branch'] = 'unknown'
        
        # Get latest commit hash
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['commit_hash'] = result.stdout.strip()
                git_info['commit_hash_short'] = git_info['commit_hash'][:7]
            else:
                git_info['commit_hash'] = 'unknown'
                git_info['commit_hash_short'] = 'unknown'
        except Exception as e:
            logger.warning(f"Error getting commit hash: {e}")
            git_info['commit_hash'] = 'unknown'
            git_info['commit_hash_short'] = 'unknown'
        
        # Get commit message
        try:
            result = subprocess.run(
                ['git', 'log', '-1', '--pretty=%s'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['commit_message'] = result.stdout.strip()
            else:
                git_info['commit_message'] = ''
        except Exception as e:
            logger.warning(f"Error getting commit message: {e}")
            git_info['commit_message'] = ''
        
        # Get commit author
        try:
            result = subprocess.run(
                ['git', 'log', '-1', '--pretty=%an'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['commit_author'] = result.stdout.strip()
            else:
                git_info['commit_author'] = ''
        except Exception as e:
            logger.warning(f"Error getting commit author: {e}")
            git_info['commit_author'] = ''
        
        # Get commit date
        try:
            result = subprocess.run(
                ['git', 'log', '-1', '--pretty=%ci'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['commit_date'] = result.stdout.strip()
            else:
                git_info['commit_date'] = ''
        except Exception as e:
            logger.warning(f"Error getting commit date: {e}")
            git_info['commit_date'] = ''
        
        # Get remote URL
        try:
            result = subprocess.run(
                ['git', 'config', '--get', 'remote.origin.url'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['remote_url'] = result.stdout.strip()
            else:
                git_info['remote_url'] = ''
        except Exception as e:
            logger.warning(f"Error getting remote URL: {e}")
            git_info['remote_url'] = ''
        
        # Check if repository has uncommitted changes
        try:
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['is_dirty'] = bool(result.stdout.strip())
            else:
                git_info['is_dirty'] = False
        except Exception as e:
            logger.warning(f"Error checking repository status: {e}")
            git_info['is_dirty'] = False
        
        # Get list of all local branches
        try:
            result = subprocess.run(
                ['git', 'branch', '--format=%(refname:short)'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                branches = [b.strip() for b in result.stdout.strip().split('\n') if b.strip()]
                git_info['branches'] = branches
            else:
                git_info['branches'] = []
        except Exception as e:
            logger.warning(f"Error getting branches: {e}")
            git_info['branches'] = []
        
        # Get list of remote branches
        try:
            result = subprocess.run(
                ['git', 'branch', '-r', '--format=%(refname:short)'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                remote_branches = [
                    b.strip().replace('origin/', '') 
                    for b in result.stdout.strip().split('\n') 
                    if b.strip() and 'origin/' in b and 'HEAD' not in b
                ]
                git_info['remote_branches'] = remote_branches
            else:
                git_info['remote_branches'] = []
        except Exception as e:
            logger.warning(f"Error getting remote branches: {e}")
            git_info['remote_branches'] = []
        
        # Get total number of commits
        try:
            result = subprocess.run(
                ['git', 'rev-list', '--count', 'HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                git_info['total_commits'] = int(result.stdout.strip())
            else:
                git_info['total_commits'] = 0
        except Exception as e:
            logger.warning(f"Error getting total commits: {e}")
            git_info['total_commits'] = 0
        
        return git_info
        
    except Exception as e:
        logger.error(f"Error getting git info for {repo_path}: {e}")
        return None


def checkout_branch(repo_path: str, branch_name: str) -> tuple[bool, str]:
    """
    Checkout a specific branch in the git repository.
    
    Args:
        repo_path: Path to the git repository
        branch_name: Name of the branch to checkout
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not is_git_repository(repo_path):
        return False, "Not a git repository"
    
    try:
        # First, fetch the latest from remote
        fetch_result = subprocess.run(
            ['git', 'fetch', 'origin'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if fetch_result.returncode != 0:
            logger.warning(f"Git fetch failed: {fetch_result.stderr}")
            # Continue anyway, branch might exist locally
        
        # Check if branch exists locally
        check_result = subprocess.run(
            ['git', 'rev-parse', '--verify', branch_name],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        branch_exists_locally = check_result.returncode == 0
        
        # Check if branch exists remotely
        check_remote_result = subprocess.run(
            ['git', 'rev-parse', '--verify', f'origin/{branch_name}'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        branch_exists_remotely = check_remote_result.returncode == 0
        
        if not branch_exists_locally and not branch_exists_remotely:
            return False, f"Branch '{branch_name}' does not exist locally or remotely"
        
        # If branch exists only remotely, create local tracking branch
        if not branch_exists_locally and branch_exists_remotely:
            result = subprocess.run(
                ['git', 'checkout', '-b', branch_name, f'origin/{branch_name}'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
        else:
            # Checkout existing local branch
            result = subprocess.run(
                ['git', 'checkout', branch_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
        
        if result.returncode == 0:
            # Pull latest changes from remote
            pull_result = subprocess.run(
                ['git', 'pull', 'origin', branch_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if pull_result.returncode != 0:
                logger.warning(f"Git pull failed: {pull_result.stderr}")
                return True, f"Switched to branch '{branch_name}' but pull failed: {pull_result.stderr}"
            
            return True, f"Successfully switched to branch '{branch_name}' and pulled latest changes"
        else:
            return False, f"Failed to checkout branch: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        return False, "Git operation timed out"
    except Exception as e:
        logger.error(f"Error checking out branch {branch_name} in {repo_path}: {e}")
        return False, f"Error: {str(e)}"


def get_all_branches(repo_path: str) -> tuple[List[str], List[str]]:
    """
    Get all local and remote branches.
    
    Args:
        repo_path: Path to the git repository
        
    Returns:
        Tuple of (local_branches, remote_branches)
    """
    if not is_git_repository(repo_path):
        return [], []
    
    local_branches = []
    remote_branches = []
    
    try:
        # Fetch latest from remote
        subprocess.run(
            ['git', 'fetch', 'origin'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Get local branches
        result = subprocess.run(
            ['git', 'branch', '--format=%(refname:short)'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            local_branches = [b.strip() for b in result.stdout.strip().split('\n') if b.strip()]
        
        # Get remote branches
        result = subprocess.run(
            ['git', 'branch', '-r', '--format=%(refname:short)'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            remote_branches = [
                b.strip().replace('origin/', '') 
                for b in result.stdout.strip().split('\n') 
                if b.strip() and 'origin/' in b and 'HEAD' not in b
            ]
    except Exception as e:
        logger.error(f"Error getting branches for {repo_path}: {e}")
    
    return local_branches, remote_branches

