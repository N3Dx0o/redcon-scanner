import os
import zipfile
import subprocess
import shutil
import uuid
import tempfile
from pathlib import Path
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

# Default excluded directories for scanning
DEFAULT_EXCLUDED_DIRS = {
    '.git', '.github', 'node_modules', '__pycache__', '.venv', 'venv', 'env', '.env',
    '.pytest_cache', 'test', 'tests', 'testdata', 'sample', 'demo',
    '.mypy_cache', '.tox'
}

def clone_git_repository(git_url: str, base_path: str) -> str:
    """
    Clone a git repository to the specified base path.
    
    Args:
        git_url: The Git repository URL
        base_path: The base directory where the project should be cloned
        
    Returns:
        The path to the cloned repository
        
    Raises:
        Exception: If git clone fails
    """
    try:
        # Generate unique project ID for directory
        unique_id = str(uuid.uuid4())[:6]
        project_dir = os.path.join(base_path, unique_id)
        
        # Ensure the base path exists
        os.makedirs(base_path, exist_ok=True)
        
        # Validate URL to prevent SSRF (block file://, gopher://, git://, etc.)
        import re as _re
        import socket as _socket
        import ipaddress as _ipaddress
        import urllib.parse as _up
        _url = (git_url or '').strip().lower()
        if not _re.match(r'^https://', _url):
            raise Exception('Invalid repository URL: only https:// URLs are allowed')
        _parsed = _up.urlparse(git_url)
        _host = _parsed.hostname or ''
        if not _host:
            raise Exception('Invalid URL: no hostname')
        # Block non-standard ports
        _port = _parsed.port or 443
        if _port not in (80, 443):
            raise Exception('Only standard ports (80/443) are allowed')
        # Resolve hostname and block all private/loopback/link-local IPs (prevents DNS rebinding)
        try:
            _addrs = {info[4][0] for info in _socket.getaddrinfo(_host, _port, type=_socket.SOCK_STREAM)}
        except Exception as _e:
            raise Exception(f'Cannot resolve hostname: {_host}')
        for _addr in _addrs:
            try:
                _ip = _ipaddress.ip_address(_addr)
            except ValueError:
                raise Exception(f'Invalid resolved IP: {_addr}')
            if (_ip.is_private or _ip.is_loopback or _ip.is_link_local or
                    _ip.is_multicast or _ip.is_reserved or _ip.is_unspecified):
                raise Exception(f'Access to internal/reserved IP ranges is not allowed ({_addr})')

        # Clone the repository
        result = subprocess.run(
            ['git', 'clone', '--depth=1', git_url, project_dir],
            capture_output=True,
            text=True,
            check=True
        )
        
        logger.info(f"Successfully cloned repository {git_url} to {project_dir}")
        return project_dir
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to clone repository {git_url}: {e.stderr}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error cloning repository {git_url}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

def _safe_extract_zip(zip_ref, dest_dir):
    """Extract zip safely, preventing ZIP Slip directory traversal."""
    import os as _os
    dest_dir = _os.path.realpath(dest_dir)
    for member in zip_ref.infolist():
        member_path = _os.path.realpath(_os.path.join(dest_dir, member.filename))
        if not member_path.startswith(dest_dir + _os.sep) and member_path != dest_dir:
            raise Exception("ZIP Slip: member would extract outside destination")
        zip_ref.extract(member, dest_dir)

def extract_zip_file(zip_file_path: str, base_path: str) -> str:
    """
    Extract a zip file to the specified base path.
    
    Args:
        zip_file_path: Path to the zip file
        base_path: The base directory where the project should be extracted
        
    Returns:
        The path to the extracted project directory
        
    Raises:
        Exception: If extraction fails
    """
    try:
        # Generate unique project ID for directory
        unique_id = str(uuid.uuid4())[:6]
        project_dir = os.path.join(base_path, unique_id)
        
        # Ensure the base path exists
        os.makedirs(base_path, exist_ok=True)
        
        # Extract zip file
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            _safe_extract_zip(zip_ref, project_dir)
        
        logger.info(f"Successfully extracted zip file {zip_file_path} to {project_dir}")
        return project_dir
        
    except zipfile.BadZipFile as e:
        error_msg = f"Invalid zip file {zip_file_path}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error extracting zip file {zip_file_path}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

def clone_git_repository_temp(git_url: str) -> str:
    """
    Clone a git repository to a random temporary directory for directory loading.
    
    Args:
        git_url: The Git repository URL
        
    Returns:
        The path to the cloned repository
        
    Raises:
        Exception: If git clone fails
    """
    try:
        # Generate unique project ID for directory in temp directory (cross-platform)
        unique_id = str(uuid.uuid4())[:8]
        temp_base = tempfile.gettempdir()
        project_dir = os.path.join(temp_base, f'wwwdot_temp_{unique_id}')
        
        # Validate URL to prevent SSRF (block file://, gopher://, git://, etc.)
        import re as _re
        import socket as _socket
        import ipaddress as _ipaddress
        import urllib.parse as _up
        _url = (git_url or '').strip().lower()
        if not _re.match(r'^https://', _url):
            raise Exception('Invalid repository URL: only https:// URLs are allowed')
        _parsed = _up.urlparse(git_url)
        _host = _parsed.hostname or ''
        if not _host:
            raise Exception('Invalid URL: no hostname')
        # Block non-standard ports
        _port = _parsed.port or 443
        if _port not in (80, 443):
            raise Exception('Only standard ports (80/443) are allowed')
        # Resolve hostname and block all private/loopback/link-local IPs (prevents DNS rebinding)
        try:
            _addrs = {info[4][0] for info in _socket.getaddrinfo(_host, _port, type=_socket.SOCK_STREAM)}
        except Exception as _e:
            raise Exception(f'Cannot resolve hostname: {_host}')
        for _addr in _addrs:
            try:
                _ip = _ipaddress.ip_address(_addr)
            except ValueError:
                raise Exception(f'Invalid resolved IP: {_addr}')
            if (_ip.is_private or _ip.is_loopback or _ip.is_link_local or
                    _ip.is_multicast or _ip.is_reserved or _ip.is_unspecified):
                raise Exception(f'Access to internal/reserved IP ranges is not allowed ({_addr})')

        # Clone the repository
        result = subprocess.run(
            ['git', 'clone', '--depth=1', git_url, project_dir],
            capture_output=True,
            text=True,
            check=True
        )
        
        logger.info(f"Successfully cloned repository {git_url} to temp directory {project_dir}")
        return project_dir
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to clone repository {git_url}: {e.stderr}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error cloning repository {git_url}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

def extract_zip_file_temp(zip_file_path: str) -> str:
    """
    Extract a zip file to a random temporary directory for directory loading.
    
    Args:
        zip_file_path: Path to the zip file
        
    Returns:
        The path to the extracted project directory
        
    Raises:
        Exception: If extraction fails
    """
    try:
        # Generate unique project ID for directory in temp directory (cross-platform)
        unique_id = str(uuid.uuid4())[:8]
        temp_base = tempfile.gettempdir()
        project_dir = os.path.join(temp_base, f'wwwdot_temp_{unique_id}')
        
        # Extract zip file
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            _safe_extract_zip(zip_ref, project_dir)
        
        logger.info(f"Successfully extracted zip file {zip_file_path} to temp directory {project_dir}")
        return project_dir
        
    except zipfile.BadZipFile as e:
        error_msg = f"Invalid zip file {zip_file_path}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error extracting zip file {zip_file_path}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

def get_project_structure(project_path: str, excluded_dirs: Optional[List[str]] = None) -> List[str]:
    """
    Get the file structure of a project, excluding specified directories.
    
    Args:
        project_path: Path to the project directory
        excluded_dirs: List of directory names to exclude (e.g., ['node_modules', '.git'])
        
    Returns:
        List of file paths relative to the project directory
    """
    if excluded_dirs is None:
        excluded_dirs = ['.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env', '.env']
    
    file_paths = []
    
    try:
        for root, dirs, files in os.walk(project_path):
            # Remove excluded directories from dirs list to prevent walking into them
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                # Get relative path from project directory
                rel_path = os.path.relpath(file_path, project_path)
                file_paths.append(rel_path)
        
        logger.info(f"Found {len(file_paths)} files in project {project_path}")
        return file_paths
        
    except Exception as e:
        logger.error(f"Error getting project structure for {project_path}: {str(e)}")
        return []

def validate_git_url(git_url: str) -> bool:
    """
    Validate if a URL is a valid Git repository URL.
    
    Args:
        git_url: The URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not git_url:
        return False
    
    # Only allow HTTPS URLs to prevent SSRF via git://, ssh://, file:// etc.
    return git_url.startswith('https://')

def get_file_extension(filename: str) -> str:
    """
    Get the file extension from a filename.
    
    Args:
        filename: The filename
        
    Returns:
        The file extension (including the dot) or empty string if no extension
    """
    return os.path.splitext(filename)[1].lower()

def is_zip_file(filename: str) -> bool:
    """
    Check if a file is a zip file based on its extension.
    
    Args:
        filename: The filename to check
        
    Returns:
        True if it's a zip file, False otherwise
    """
    return get_file_extension(filename) == '.zip'

def cleanup_temp_files(file_path: str) -> None:
    """
    Clean up temporary files.
    
    Args:
        file_path: Path to the file to delete
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Cleaned up temporary file: {file_path}")
    except Exception as e:
        logger.warning(f"Failed to clean up temporary file {file_path}: {str(e)}")

def get_project_size(project_path: str) -> int:
    """
    Get the total size of a project directory in bytes.
    
    Args:
        project_path: Path to the project directory
        
    Returns:
        Total size in bytes
    """
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(project_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
        return total_size
    except Exception as e:
        logger.error(f"Error calculating project size for {project_path}: {str(e)}")
        return 0

def filter_target_dirs(base_dir: str, excluded_dirs: list[str], included_dirs: list[str]) -> list[str]:
    """
    Filter target directories based on inclusion and exclusion rules.
    
    Args:
        base_dir: Base directory to scan
        excluded_dirs: List of directories to exclude
        included_dirs: List of directories to include (if specified, cancels excluded_dirs)
    
    Returns:
        List of relative directory paths to scan
    """
    base_dir_path = Path(base_dir)
    
    # If included_dirs is not empty, return only those directories and their subdirectories
    # BUT still apply default exclusion rules
    if included_dirs:
        result_dirs = []
        for d in included_dirs:
            included_path = base_dir_path / d
            try:
                if included_path.exists() and included_path.is_dir():
                    relative_path = included_path.relative_to(base_dir_path)
                    relative_path_str = str(relative_path)
                    
                    # Check if directory name itself is in default excluded dirs
                    if included_path.name in DEFAULT_EXCLUDED_DIRS:
                        continue
                    
                    # Check if any part of the path matches a default excluded dir
                    path_parts = relative_path.parts
                    is_excluded = any(part in DEFAULT_EXCLUDED_DIRS for part in path_parts)
                    if is_excluded:
                        continue
                    
                    # Add the directory itself
                    result_dirs.append(relative_path_str)
                    
                    # Recursively collect all subdirectories
                    for subdir in included_path.rglob('*'):
                        if subdir.is_dir():
                            try:
                                subdir_relative = subdir.relative_to(base_dir_path)
                                subdir_relative_str = str(subdir_relative)
                                
                                # Skip root directory
                                if not subdir_relative_str or subdir_relative_str == '.':
                                    continue
                                
                                # Check if directory name itself is in default excluded dirs
                                if subdir.name in DEFAULT_EXCLUDED_DIRS:
                                    continue
                                
                                # Check if any part of the path matches a default excluded dir
                                subdir_parts = subdir_relative.parts
                                is_subdir_excluded = any(part in DEFAULT_EXCLUDED_DIRS for part in subdir_parts)
                                if is_subdir_excluded:
                                    continue
                                
                                result_dirs.append(subdir_relative_str)
                            except (OSError, ValueError):
                                continue
            except (OSError, ValueError):
                continue
        return list(set(result_dirs))
    
    # Otherwise, collect all directories and filter out excluded ones
    all_dirs = []
    excluded_paths = set()
    
    # Build set of excluded relative paths for efficient lookup
    for d in excluded_dirs:
        if not d or d == '.':
            # Excluding root directory means excluding everything
            return []
        
        # Try to resolve the excluded directory path
        # It could be:
        # 1. A relative path from base_dir (e.g., "src", "app/utils")
        # 2. Just a directory name that exists somewhere in the tree (e.g., "node_modules")
        excluded_path = base_dir_path / d
        try:
            if excluded_path.exists() and excluded_path.is_dir():
                # It's a valid relative path from base_dir
                relative_excluded = excluded_path.relative_to(base_dir_path)
                excluded_paths.add(str(relative_excluded))
            else:
                # It might be just a directory name - we'll check by name during iteration
                excluded_paths.add(d)
        except (OSError, ValueError):
            # If path resolution fails, treat it as a directory name to match
            excluded_paths.add(d)
    
    # Collect all directories recursively
    for p in base_dir_path.rglob('*'):
        if p.is_dir():
            try:
                relative_p = p.relative_to(base_dir_path)
                relative_p_str = str(relative_p)
                
                # Skip root directory (empty string or ".")
                if not relative_p_str or relative_p_str == '.':
                    continue
                
                # Check if directory name itself is in default excluded dirs
                if p.name in DEFAULT_EXCLUDED_DIRS:
                    continue
                
                # Check if any part of the path matches a default excluded dir
                path_parts = relative_p.parts
                is_excluded = any(part in DEFAULT_EXCLUDED_DIRS for part in path_parts)
                
                if is_excluded:
                    continue
                
                # Skip if path is in user excluded dirs or is a subdirectory of an excluded dir
                is_user_excluded = False
                for excluded_path in excluded_paths:
                    if not excluded_path:  # Skip empty excluded paths
                        continue
                    
                    # Check if current path matches the excluded path exactly
                    if relative_p_str == excluded_path:
                        is_user_excluded = True
                        break
                    
                    # Check if current path is a subdirectory of excluded path
                    # First check if it starts with the excluded path (for relative paths)
                    if relative_p_str.startswith(excluded_path + '/'):
                        is_user_excluded = True
                        break
                    
                    # Also check if the excluded path is a directory name that appears in the path
                    # This handles cases where excluded_dirs contains just directory names
                    if excluded_path in path_parts:
                        # Find the index of the excluded directory in the path
                        excluded_index = path_parts.index(excluded_path)
                        # If it's at the start or anywhere in the path, exclude this directory
                        # and all its subdirectories
                        is_user_excluded = True
                        break
                
                if is_user_excluded:
                    continue
                
                # Validate path exists and add relative path
                if p.exists() and p.is_dir():
                    all_dirs.append(relative_p_str)
            except (OSError, ValueError):
                continue
    
    return list(set(all_dirs))
