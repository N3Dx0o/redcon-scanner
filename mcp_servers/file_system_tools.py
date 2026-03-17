#!/usr/bin/env python3
"""
MCP Code Audit File Explorer Server

A focused filesystem server designed specifically for code auditor agents to explore and read files
in a codebase. This server acts as a file explorer with intelligent language detection and 
structured output that helps auditors understand the codebase structure and examine files.

IMPORTANT SECURITY FEATURE:
- All file operations are restricted to a base directory specified at startup
- The server will never access files outside the designated base directory
- This prevents AI agents from accessing sensitive system files or other projects

Key Features:
- Pure file exploration and reading capabilities
- Language-aware file detection and filtering
- Recursive directory traversal with depth control
- Structured JSON output for easy AI agent parsing
- Comprehensive error handling with clear messages
- Support for hidden files and directories
- File size and metadata information
- One focused cross-reference function for vulnerability analysis
- Security: Restricted to base directory only

Supported Languages:
- Rust, Solidity, Python, JavaScript, TypeScript
- C/C++, Go, Java, PHP, Ruby, Swift, Kotlin, Scala

Usage for Code Auditor Agents:
1. Use explore_directory() to navigate the codebase structure
2. Use read_file() to examine specific files
3. Use get_codebase_overview() to understand project structure
4. Use find_cross_references() for vulnerability analysis when needed

Command Line Usage:
    python file_system_tools.py <base_directory>
    
Example:
    python file_system_tools.py /path/to/project
"""

import asyncio
import json
import os
import sys
import fnmatch
import glob
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from mcp.server import FastMCP

# Comprehensive language definitions with file extensions and descriptions
LANGUAGES = {
    'rust': {
        'extensions': ['.rs'],
        'description': 'Rust programming language files',
        'common_patterns': ['*.rs', 'lib.rs', 'main.rs', 'Cargo.toml']
    },
    'solidity': {
        'extensions': ['.sol'],
        'description': 'Solidity smart contract files',
        'common_patterns': ['*.sol', 'contracts/*.sol', '*.contract']
    },
    'python': {
        'extensions': ['.py', '.pyw', '.pyi'],
        'description': 'Python programming language files',
        'common_patterns': ['*.py', '__init__.py', 'main.py', 'requirements.txt']
    },
    'javascript': {
        'extensions': ['.js', '.mjs', '.cjs'],
        'description': 'JavaScript programming language files',
        'common_patterns': ['*.js', 'index.js', 'app.js', 'package.json']
    },
    'typescript': {
        'extensions': ['.ts', '.tsx'],
        'description': 'TypeScript programming language files',
        'common_patterns': ['*.ts', '*.tsx', 'index.ts', 'tsconfig.json']
    },
    'c': {
        'extensions': ['.c', '.h'],
        'description': 'C programming language files',
        'common_patterns': ['*.c', '*.h', 'main.c', '*.h']
    },
    'cpp': {
        'extensions': ['.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hxx', '.h++'],
        'description': 'C++ programming language files',
        'common_patterns': ['*.cpp', '*.hpp', 'main.cpp', '*.h']
    },
    'go': {
        'extensions': ['.go'],
        'description': 'Go programming language files',
        'common_patterns': ['*.go', 'main.go', 'go.mod', 'go.sum']
    },
    'java': {
        'extensions': ['.java'],
        'description': 'Java programming language files',
        'common_patterns': ['*.java', 'pom.xml', 'build.gradle']
    },
    'php': {
        'extensions': ['.php', '.phtml'],
        'description': 'PHP programming language files',
        'common_patterns': ['*.php', 'index.php', 'composer.json']
    },
    'ruby': {
        'extensions': ['.rb'],
        'description': 'Ruby programming language files',
        'common_patterns': ['*.rb', 'Gemfile', 'Rakefile']
    },
    'swift': {
        'extensions': ['.swift'],
        'description': 'Swift programming language files',
        'common_patterns': ['*.swift', 'Package.swift']
    },
    'kotlin': {
        'extensions': ['.kt', '.kts'],
        'description': 'Kotlin programming language files',
        'common_patterns': ['*.kt', '*.kts', 'build.gradle.kts']
    },
    'scala': {
        'extensions': ['.scala', '.sc'],
        'description': 'Scala programming language files',
        'common_patterns': ['*.scala', '*.sc', 'build.sbt']
    }
}

# Global base directory - set at startup
BASE_DIRECTORY: Optional[Path] = None

# Create FastMCP server instance
app = FastMCP("code-audit-filesystem-server")


def set_base_directory(base_dir: str) -> None:
    """
    Set the base directory for all file operations.
    
    Args:
        base_dir: Path to the base directory to restrict operations to
        
    Raises:
        ValueError: If the base directory is invalid or doesn't exist
        SystemExit: If the base directory cannot be set
    """
    global BASE_DIRECTORY
    
    try:
        base_path = Path(base_dir).resolve()
        
        if not base_path.exists():
            raise ValueError(f"Base directory does not exist: {base_dir}")
        
        if not base_path.is_dir():
            raise ValueError(f"Base directory is not a directory: {base_dir}")
        
        # Check if we can read the directory
        try:
            list(base_path.iterdir())
        except PermissionError:
            raise ValueError(f"Permission denied accessing base directory: {base_dir}")
        
        BASE_DIRECTORY = base_path
        print(f"Base directory set to: {BASE_DIRECTORY}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error setting base directory '{base_dir}': {str(e)}", file=sys.stderr)
        sys.exit(1)


def validate_path_within_base(path: str) -> Tuple[bool, str, Optional[Path]]:
    """
    Validate a path and ensure it's within the base directory.
    
    Args:
        path: Path to validate
        
    Returns:
        Tuple of (is_valid, error_message, normalized_path)
    """
    global BASE_DIRECTORY
    
    if BASE_DIRECTORY is None:
        return False, "Base directory not set", None
    
    try:
        # Resolve the path
        if os.path.isabs(path):
            target_path = Path(path).resolve()
        else:
            # Relative path - resolve relative to base directory
            target_path = (BASE_DIRECTORY / path).resolve()
        
        # Check if the path exists
        if not target_path.exists():
            return False, f"Path not found: {path}", None
        
        # Security check: ensure the path is within base directory
        try:
            target_path.relative_to(BASE_DIRECTORY)
        except ValueError:
            return False, f"Path is outside base directory: {path}", None
        
        return True, "", target_path
        
    except Exception as e:
        return False, f"Invalid path '{path}': {str(e)}", None


def get_relative_path(absolute_path: Path) -> str:
    """
    Get the relative path from the base directory.
    
    Args:
        absolute_path: Absolute path within the base directory
        
    Returns:
        Relative path string
    """
    global BASE_DIRECTORY
    
    if BASE_DIRECTORY is None:
        return str(absolute_path)
    
    try:
        return str(absolute_path.relative_to(BASE_DIRECTORY))
    except ValueError:
        return str(absolute_path)


def get_language_from_extension(file_path: Path) -> Optional[str]:
    """
    Detect programming language from file extension.
    
    Args:
        file_path: Path object representing the file
        
    Returns:
        Language name (e.g., 'python', 'rust') or None if not recognized
        
    Example:
        >>> get_language_from_extension(Path("main.py"))
        'python'
        >>> get_language_from_extension(Path("lib.rs"))
        'rust'
    """
    suffix = file_path.suffix.lower()
    for lang, lang_info in LANGUAGES.items():
        if suffix in lang_info['extensions']:
            return lang
    return None


def get_language_info(language: str) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive information about a programming language.
    
    Args:
        language: Language name (e.g., 'python', 'rust')
        
    Returns:
        Dictionary with language information or None if not found
        
    Example:
        >>> get_language_info('python')
        {'extensions': ['.py', '.pyw', '.pyi'], 'description': '...', 'common_patterns': [...]}
    """
    return LANGUAGES.get(language.lower())


def matches_pattern(file_path: Path, patterns: List[str], case_sensitive: bool = False) -> bool:
    """
    Check if file matches any of the given patterns using Unix shell-style wildcards.
    
    Args:
        file_path: Path object representing the file
        patterns: List of pattern strings (e.g., ['*.py', 'test_*'])
        case_sensitive: Whether pattern matching should be case sensitive
        
    Returns:
        True if file matches any pattern, False otherwise
        
    Example:
        >>> matches_pattern(Path("test_file.py"), ["*.py", "test_*"])
        True
        >>> matches_pattern(Path("README.md"), ["*.py", "*.rs"])
        False
    """
    name = file_path.name if case_sensitive else file_path.name.lower()
    for pattern in patterns:
        pattern_lower = pattern if case_sensitive else pattern.lower()
        if fnmatch.fnmatch(name, pattern_lower):
            return True
    return False


def should_include_file(file_path: Path, patterns: List[str]) -> bool:
    """
    Check if file should be included based on pattern filters.
    
    This function applies pattern filters. A file is included if:
    1. No patterns are specified (include all), OR
    2. File matches pattern filter (if specified)
    
    Args:
        file_path: Path object representing the file
        patterns: List of pattern strings to filter by (e.g., ['*.py', 'test_*'])
        
    Returns:
        True if file should be included, False otherwise
        
    Example:
        >>> should_include_file(Path("main.py"), ["*.py"])
        True
        >>> should_include_file(Path("main.py"), ["*.rs"])
        False
    """
    # If no patterns specified, include all files
    if not patterns:
        return True
    
    # Check pattern filter
    return matches_pattern(file_path, patterns)


def get_file_metadata(file_path: Path) -> Dict[str, Any]:
    """
    Get comprehensive metadata about a file.
    
    Args:
        file_path: Path object representing the file
        
    Returns:
        Dictionary containing file metadata
        
    Example:
        >>> get_file_metadata(Path("main.py"))
        {
            'name': 'main.py',
            'size': 1024,
            'language': 'python',
            'extension': '.py',
            'is_hidden': False,
            'modified_time': '2024-01-01T12:00:00'
        }
    """
    try:
        stat = file_path.stat()
        return {
            'name': file_path.name,
            'size': stat.st_size,
            'language': get_language_from_extension(file_path),
            'extension': file_path.suffix.lower(),
            'is_hidden': file_path.name.startswith('.'),
            'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'is_file': file_path.is_file(),
            'is_directory': file_path.is_dir()
        }
    except (OSError, IOError) as e:
        return {
            'name': file_path.name,
            'error': f"Could not read metadata: {str(e)}",
            'is_hidden': file_path.name.startswith('.')
        }


def validate_path(path: str) -> Tuple[bool, str, Optional[Path]]:
    """
    Validate a file or directory path and ensure it's within the base directory.
    
    Args:
        path: String path to validate
        
    Returns:
        Tuple of (is_valid, error_message, normalized_path)
        
    Example:
        >>> validate_path("src/main.py")
        (True, "", Path("/base/dir/src/main.py"))
        >>> validate_path("/outside/path")
        (False, "Path is outside base directory: /outside/path", None)
    """
    return validate_path_within_base(path)


def smart_resolve_file_path(path: str) -> Tuple[bool, str, Optional[Path]]:
    """
    Smartly resolve a file path with multiple fallback strategies.
    
    This function tries multiple strategies to find a file:
    1. Use the path as-is (exact match)
    2. Extract filename and search recursively with exact name match
    3. Try case-insensitive matching of filename
    4. Try glob patterns with wildcards
    
    Args:
        path: String path to resolve
        
    Returns:
        Tuple of (is_valid, error_message, normalized_path)
    """
    global BASE_DIRECTORY
    
    if BASE_DIRECTORY is None:
        return False, "Base directory not set", None
    
    # Strategy 1: Try the path as-is (exact match)
    is_valid, error_msg, resolved_path = validate_path_within_base(path)
    if is_valid and resolved_path and resolved_path.exists() and resolved_path.is_file():
        return True, "", resolved_path
    
    # Strategy 2 & 3: Extract filename and search recursively (exact and case-insensitive)
    filename = Path(path).name
    filename_lower = filename.lower()
    
    # Search recursively for files matching the filename (exact or case-insensitive)
    try:
        matches_found = []
        for file_path in BASE_DIRECTORY.rglob('*'):
            # Ensure it's within base directory
            try:
                file_path.relative_to(BASE_DIRECTORY)
            except ValueError:
                continue
            
            # Check if it's a file
            if not file_path.is_file():
                continue
            
            # Try exact match first
            if file_path.name == filename:
                return True, "", file_path.resolve()
            
            # Then try case-insensitive match
            if file_path.name.lower() == filename_lower:
                matches_found.append(file_path)
        
        # If we found case-insensitive matches, return the first one
        if matches_found:
            return True, "", matches_found[0].resolve()
    except Exception:
        pass
    
    # Strategy 4: Try glob patterns
    try:
        # Try various glob patterns
        glob_patterns = [
            f"**/{filename}",
            f"**/*{filename}",
            f"**/{filename}*",
            f"**/*{filename}*"
        ]
        
        for pattern in glob_patterns:
            matches = list(BASE_DIRECTORY.glob(pattern))
            
            for match in matches:
                try:
                    match.relative_to(BASE_DIRECTORY)
                    if match.is_file():
                        return True, "", match.resolve()
                except ValueError:
                    continue
    except Exception:
        pass
    
    # All strategies failed
    return False, f"File not found: {path}. Tried exact path, filename search, and case-insensitive matching.", None



@app.tool(
    description="Read the contents of a file with configurable encoding and comprehensive metadata. "
               "This tool is essential for AI agents to examine source code, configuration files, "
               "and documentation. Returns both file content and metadata for better understanding.",
    title="Read File",
    annotations={
        "path": "Absolute or relative path to the file to read",
        "encoding": "File encoding (default: utf-8). Common encodings: utf-8, ascii, latin-1, cp1252"
    }
)
async def read_file(
    path: str,
    encoding: str = "utf-8"
) -> str:
    """
    Read the contents of a file with comprehensive error handling and metadata.
    
    This function is designed for AI agents to safely read files during code analysis.
    It provides detailed error messages and file metadata to help agents understand
    the context and handle errors gracefully.
    
    It uses smart path resolution to find files even when the exact path isn't known,
    trying multiple strategies including filename search and case-insensitive matching.
    
    Args:
        path: Path to the file to read (can be absolute or relative)
        encoding: File encoding to use when reading the file (default: utf-8)
                 Common encodings: utf-8, ascii, latin-1, cp1252, utf-16
    
    Returns:
        - None: If the target is detected as a binary file (to save tokens)
        - JSON string containing:
          - content: File contents as string
          - metadata: File information (size, language, modification time, etc.)
          - success: Boolean indicating if read was successful
          - error: Error message if read failed
        
    Raises:
        FileNotFoundError: If the file does not exist
        ValueError: If the path is not a file
        UnicodeDecodeError: If the file cannot be decoded with specified encoding
        PermissionError: If the file cannot be read due to permissions
        
    Example:
        >>> read_file("/path/to/main.py")
        '{"content": "print(\'Hello World\')", "metadata": {...}, "success": true}'
    """
    # Use smart path resolution to find the file
    is_valid, error_msg, file_path = smart_resolve_file_path(path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "error": error_msg,
            "content": "",
            "metadata": {},
            "original_path": path
        }, indent=2)
    
    if not file_path or not file_path.is_file():
        return json.dumps({
            "success": False,
            "error": f"Path is not a file: {path}",
            "content": "",
            "metadata": get_file_metadata(file_path) if file_path else {},
            "original_path": path
        }, indent=2)
    
    try:
        # Detect binary files early by sampling bytes
        with open(file_path, 'rb') as fb:
            sample = fb.read(4096)
        # Heuristic 1: null byte indicates binary
        if b"\x00" in sample:
            return None
        # Heuristic 2: proportion of printable text bytes
        if sample:
            printable_or_ws = {9, 10, 13}  # tab, lf, cr
            textish_count = sum((32 <= b <= 126) or (b in printable_or_ws) for b in sample)
            if (textish_count / len(sample)) < 0.70:
                return None
        
        # Read file content
        with open(file_path, 'r', encoding=encoding) as f:
            content = f.read()
        
        # Get file metadata
        metadata = get_file_metadata(file_path)
        metadata.update({
            "encoding_used": encoding,
            "content_length": len(content),
            "line_count": len(content.splitlines()) if content else 0
        })
        
        result = {
            "success": True,
            "content": content,
            "metadata": metadata,
            "error": None,
            "original_path": path,
            "resolved_path": str(file_path),
            "relative_path": get_relative_path(file_path)
        }
        
        return json.dumps(result, indent=2)
        
    except UnicodeDecodeError as e:
        error_msg = f"Could not decode file with encoding '{encoding}': {str(e)}. Try a different encoding like 'latin-1' or 'cp1252'."
        return json.dumps({
            "success": False,
            "error": error_msg,
            "content": "",
            "metadata": get_file_metadata(file_path),
            "original_path": path,
            "resolved_path": str(file_path) if file_path else ""
        }, indent=2)
        
    except PermissionError as e:
        error_msg = f"Permission denied reading file '{path}': {str(e)}"
        return json.dumps({
            "success": False,
            "error": error_msg,
            "content": "",
            "metadata": get_file_metadata(file_path),
            "original_path": path,
            "resolved_path": str(file_path) if file_path else ""
        }, indent=2)
        
    except Exception as e:
        error_msg = f"Unexpected error reading file '{path}': {str(e)}"
        return json.dumps({
            "success": False,
            "error": error_msg,
            "content": "",
            "metadata": get_file_metadata(file_path),
            "original_path": path,
            "resolved_path": str(file_path) if file_path else ""
        }, indent=2)


@app.tool(
    description="Explore directory contents with intelligent language detection and comprehensive metadata. "
               "This tool is essential for code auditor agents to navigate codebase structure, understand "
               "project organization, and identify files of interest. Supports recursive traversal with "
               "language-based filtering.",
    title="Explore Directory",
    annotations={
        "path": "Absolute or relative path to the directory to explore",
        "recursive": "Whether to traverse subdirectories recursively (default: False)",
        "language_filter": "Filter by programming language (e.g., 'python', 'rust', 'solidity')"
    }
)
async def explore_directory(
    path: str,
    recursive: Any = False,
    language_filter: Optional[Any] = None
) -> str:
    """
    Explore directory contents with comprehensive filtering and metadata for code auditor agents.
    
    This function provides code auditor agents with detailed information about directory structure,
    file types, and metadata to help them understand codebase organization and identify
    relevant files for security analysis.
    
    Args:
        path: Path to the directory to explore (can be absolute or relative)
        recursive: Whether to traverse subdirectories recursively
        language_filter: Programming language to filter by (e.g., 'python', 'rust', 'solidity')
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - path: Normalized directory path
        - recursive: Whether recursive exploration was used
        - filters: Applied filters (language)
        - items: Array of file/directory objects with metadata
        - summary: Statistics about the exploration (counts by type, language, etc.)
        - error: Error message if operation failed
        
    Example:
        >>> explore_directory("/project", language_filter="python")
        '{"success": true, "path": "/project", "items": [...], "summary": {...}}'
    """
    # Flexible parameter handling for LLM compatibility
    if isinstance(recursive, dict):
        recursive = False
    elif not isinstance(recursive, bool):
        try:
            recursive = bool(recursive)
        except (TypeError, ValueError):
            recursive = False
    
    if isinstance(language_filter, dict):
        language_filter = None
    elif not isinstance(language_filter, str) and language_filter is not None:
        try:
            language_filter = str(language_filter)
        except (TypeError, ValueError):
            language_filter = None
    
    # Validate language filter
    if language_filter and language_filter.lower() not in LANGUAGES:
        return json.dumps({
            "success": False,
            "error": f"Unsupported language filter: {language_filter}. Supported languages: {', '.join(LANGUAGES.keys())}",
            "path": path,
            "items": [],
            "summary": {}
        }, indent=2)
    
    # Validate and normalize the path
    is_valid, error_msg, dir_path = validate_path(path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "error": error_msg,
            "path": path,
            "items": [],
            "summary": {}
        }, indent=2)
    
    if not dir_path.is_dir():
        return json.dumps({
            "success": False,
            "error": f"Path is not a directory: {path}",
            "path": str(dir_path),
            "items": [],
            "summary": {}
        }, indent=2)
    
    try:
        items = []
        summary = {
            "total_files": 0,
            "total_directories": 0,
            "files_by_language": {},
            "files_by_extension": {},
            "total_size_bytes": 0,
            "depth_reached": 0
        }
        
        if recursive:
            for root, dirs, files in os.walk(dir_path):
                # Calculate depth
                depth = len(Path(root).relative_to(dir_path).parts)
                summary["depth_reached"] = max(summary["depth_reached"], depth)
                
                # Check depth limit (hardcoded to 20)
                if depth > 20:
                    dirs[:] = []  # Don't go deeper
                    continue
                
                # Process directories
                for dir_name in dirs:
                    dir_path_item = Path(root) / dir_name
                    items.append({
                        "path": str(dir_path_item),
                        "name": dir_name,
                        "type": "directory",
                        "depth": depth,
                        "is_hidden": dir_name.startswith('.'),
                        "relative_path": get_relative_path(dir_path_item)
                    })
                    summary["total_directories"] += 1
                
                # Process files
                for file_name in files:
                    file_path = Path(root) / file_name
                    
                    # Get file metadata
                    metadata = get_file_metadata(file_path)
                    file_language = metadata.get("language")
                    
                    # Apply language filter
                    if language_filter and file_language != language_filter.lower():
                        continue
                    
                    item_data = {
                        "path": str(file_path),
                        "name": file_name,
                        "type": "file",
                        "depth": depth,
                        "relative_path": get_relative_path(file_path),
                        **metadata
                    }
                    items.append(item_data)
                    
                    # Update summary
                    summary["total_files"] += 1
                    summary["total_size_bytes"] += metadata.get("size", 0)
                    
                    # Count by language
                    if file_language:
                        summary["files_by_language"][file_language] = summary["files_by_language"].get(file_language, 0) + 1
                    
                    # Count by extension
                    ext = metadata.get("extension", "")
                    if ext:
                        summary["files_by_extension"][ext] = summary["files_by_extension"].get(ext, 0) + 1
        else:
            # Non-recursive listing
            for item in dir_path.iterdir():
                if item.is_dir():
                    items.append({
                        "path": str(item),
                        "name": item.name,
                        "type": "directory",
                        "is_hidden": item.name.startswith('.'),
                        "relative_path": get_relative_path(item)
                    })
                    summary["total_directories"] += 1
                else:
                    # Get file metadata
                    metadata = get_file_metadata(item)
                    file_language = metadata.get("language")
                    
                    # Apply language filter
                    if language_filter and file_language != language_filter.lower():
                        continue
                    
                    item_data = {
                        "path": str(item),
                        "name": item.name,
                        "type": "file",
                        "relative_path": get_relative_path(item),
                        **metadata
                    }
                    items.append(item_data)
                    
                    # Update summary
                    summary["total_files"] += 1
                    summary["total_size_bytes"] += metadata.get("size", 0)
                    
                    # Count by language
                    if file_language:
                        summary["files_by_language"][file_language] = summary["files_by_language"].get(file_language, 0) + 1
                    
                    # Count by extension
                    ext = metadata.get("extension", "")
                    if ext:
                        summary["files_by_extension"][ext] = summary["files_by_extension"].get(ext, 0) + 1
        
        result = {
            "success": True,
            "path": str(dir_path),
            "recursive": recursive,
            "filters": {
                "language_filter": language_filter,
                "max_depth": 20
            },
            "items": items,
            "summary": summary,
            "total_count": len(items),
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_msg = f"Error listing directory '{path}': {str(e)}"
        return json.dumps({
            "success": False,
            "error": error_msg,
            "path": str(dir_path),
            "items": [],
            "summary": {},
            "total_count": 0
        }, indent=2)



@app.tool(
    description="Get file metadata without reading the file content. This tool is useful for "
               "AI agents to quickly gather information about files before deciding whether "
               "to read their contents.",
    title="Get File Metadata",
    annotations={
        "path": "Absolute or relative path to the file"
    }
)
async def get_file_metadata_tool(path: str) -> str:
    """
    Get comprehensive metadata about a file without reading its content.
    
    This function provides AI agents with file information such as size, language,
    modification time, and other attributes without the overhead of reading the
    entire file content. Useful for making decisions about which files to examine.
    
    Args:
        path: Path to the file to get metadata for
        
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - metadata: File metadata dictionary
        - error: Error message if operation failed
        
    Example:
        >>> get_file_metadata_tool("/path/to/main.py")
        '{"success": true, "metadata": {"name": "main.py", "size": 1024, "language": "python", ...}}'
    """
    # Validate and normalize the path
    is_valid, error_msg, file_path = validate_path(path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "metadata": {},
            "error": error_msg
        }, indent=2)
    
    if not file_path.is_file():
        return json.dumps({
            "success": False,
            "metadata": get_file_metadata(file_path),
            "error": f"Path is not a file: {path}"
        }, indent=2)
    
    try:
        metadata = get_file_metadata(file_path)
        
        result = {
            "success": True,
            "metadata": metadata,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_msg = f"Error getting file metadata for '{path}': {str(e)}"
        return json.dumps({
            "success": False,
            "metadata": {},
            "error": error_msg
        }, indent=2)


@app.tool(
    description="Get a comprehensive overview of the codebase structure and composition. This tool "
               "provides code auditor agents with a high-level understanding of the project, "
               "including language distribution, key directories, and important files.",
    title="Get Codebase Overview",
    annotations={
        "path": "Root directory to analyze (absolute or relative path, defaults to base directory) - can be string or None"
    }
)
async def get_codebase_overview(
    path: Optional[Any] = None
) -> str:
    """
    Get a comprehensive overview of the codebase structure and composition.
    
    This function provides code auditor agents with a high-level understanding of the project,
    including language distribution, key directories, important files, and overall structure.
    It's designed to give auditors a quick understanding of what they're working with.
    
    Args:
        path: Root directory to analyze (can be absolute or relative, defaults to base directory)
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - overview: Comprehensive codebase overview including:
                  * total_files: Total number of files
                  * total_directories: Total number of directories
                  * languages: Distribution of programming languages
                  * key_files: Important files (config, main, etc.)
                  * directory_structure: High-level directory organization
                  * file_size_distribution: Size ranges of files
                  * security_relevant_files: Files that might contain sensitive info
        - error: Error message if operation failed
        
    Example:
        >>> get_codebase_overview()
        '{"success": true, "overview": {"total_files": 150, "languages": {"python": 45, "rust": 30, ...}, ...}}'
    """
    # Flexible parameter handling for LLM compatibility
    if path is None or isinstance(path, dict):
        # Handle case where LLM passes empty dict or None
        global BASE_DIRECTORY
        if BASE_DIRECTORY is None:
            return json.dumps({
                "success": False,
                "overview": {},
                "error": "No path specified and base directory not set"
            }, indent=2)
        path = str(BASE_DIRECTORY)
    elif not isinstance(path, str):
        # Handle any other unexpected types by converting to string
        path = str(path)
    
    # Validate and normalize the path
    is_valid, error_msg, dir_path = validate_path(path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "overview": {},
            "error": error_msg
        }, indent=2)
    
    if not dir_path.is_dir():
        return json.dumps({
            "success": False,
            "overview": {},
            "error": f"Path is not a directory: {path}"
        }, indent=2)
    
    try:
        overview = {
            "total_files": 0,
            "total_directories": 0,
            "languages": {},
            "extensions": {},
            "key_files": [],
            "directory_structure": {},
            "file_size_distribution": {
                "small_files": 0,    # < 1KB
                "medium_files": 0,   # 1KB - 100KB
                "large_files": 0,    # 100KB - 1MB
                "very_large_files": 0 # > 1MB
            },
            "security_relevant_files": [],
            "total_size_bytes": 0,
            "depth_analyzed": 0
        }
        
        # Key file patterns to identify important files
        key_file_patterns = [
            'main.*', 'index.*', 'app.*', 'server.*',
            'config.*', 'settings.*', 'package.json', 'requirements.txt',
            'Cargo.toml', 'go.mod', 'pom.xml', 'build.gradle',
            'Dockerfile', 'docker-compose.*', 'Makefile',
            'README.*', 'LICENSE.*', 'CHANGELOG.*'
        ]
        
        # Security-relevant file patterns
        security_patterns = [
            '*.key', '*.pem', '*.p12', '*.pfx', '*.jks',
            '*.env', '.env*', 'secrets.*', 'credentials.*',
            'config.*', 'settings.*', '*.conf', '*.ini'
        ]
        
        for root, dirs, filenames in os.walk(dir_path):
            # Calculate depth
            depth = len(Path(root).relative_to(dir_path).parts)
            overview["depth_analyzed"] = max(overview["depth_analyzed"], depth)
            
            # Check depth limit (hardcoded to 20)
            if depth > 20:
                dirs[:] = []  # Don't go deeper
                continue
            
            # Track directory structure
            rel_path = get_relative_path(Path(root))
            if rel_path != ".":
                overview["directory_structure"][rel_path] = {
                    "file_count": 0,
                    "subdir_count": len(dirs)
                }
            
            # Process files
            for filename in filenames:
                file_path = Path(root) / filename
                metadata = get_file_metadata(file_path)
                
                # Update counts
                overview["total_files"] += 1
                overview["total_size_bytes"] += metadata.get("size", 0)
                
                # Count by language
                language = metadata.get("language")
                if language:
                    overview["languages"][language] = overview["languages"].get(language, 0) + 1
                
                # Count by extension
                ext = metadata.get("extension", "")
                if ext:
                    overview["extensions"][ext] = overview["extensions"].get(ext, 0) + 1
                
                # File size distribution
                size = metadata.get("size", 0)
                if size < 1024:
                    overview["file_size_distribution"]["small_files"] += 1
                elif size < 1024 * 100:
                    overview["file_size_distribution"]["medium_files"] += 1
                elif size < 1024 * 1024:
                    overview["file_size_distribution"]["large_files"] += 1
                else:
                    overview["file_size_distribution"]["very_large_files"] += 1
                
                # Check for key files
                if any(fnmatch.fnmatch(filename.lower(), pattern.lower()) for pattern in key_file_patterns):
                    overview["key_files"].append({
                        "path": get_relative_path(file_path),
                        "name": filename,
                        "size": size,
                        "language": language
                    })
                
                # Check for security-relevant files
                if any(fnmatch.fnmatch(filename.lower(), pattern.lower()) for pattern in security_patterns):
                    overview["security_relevant_files"].append({
                        "path": get_relative_path(file_path),
                        "name": filename,
                        "size": size,
                        "language": language
                    })
                
                # Update directory structure
                if rel_path != ".":
                    overview["directory_structure"][rel_path]["file_count"] += 1
        
        # Count directories
        for root, dirs, filenames in os.walk(dir_path):
            depth = len(Path(root).relative_to(dir_path).parts)
            if depth <= 20:
                overview["total_directories"] += len(dirs)
        
        result = {
            "success": True,
            "overview": overview,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_msg = f"Error analyzing codebase overview for '{path}': {str(e)}"
        return json.dumps({
            "success": False,
            "overview": {},
            "error": error_msg
        }, indent=2)


@app.tool(
    description="Find cross-references for specific symbols, functions, or variables across the codebase. "
               "This focused tool helps code auditor agents understand how code elements are used "
               "throughout the project, which is essential for vulnerability analysis and impact assessment.",
    title="Find Cross References",
    annotations={
        "symbol": "Symbol to search for (function name, variable, class, etc.)",
        "file_types": "Limit search to specific file types (e.g., ['python', 'rust', 'solidity']) - can be list, string, or None"
    }
)
async def find_cross_references(
    symbol: str,
    file_types: Optional[Any] = None
) -> str:
    """
    Find cross-references for specific symbols, functions, or variables across the codebase.
    
    This focused function helps code auditor agents understand how code elements are used
    throughout the project. It's specifically designed for vulnerability analysis and
    impact assessment by finding all references to a particular symbol.
    
    Key Features:
    - Focused symbol search for cross-reference analysis
    - Language-aware filtering for better precision
    - Context-aware matching (function calls, variable usage, etc.)
    - Detailed location information for each reference
    - Binary file detection and skipping
    - Encoding detection and fallback handling
    
    Args:
        symbol: Symbol to search for (function name, variable, class, etc.)
        file_types: List of programming languages to limit search scope (e.g., ['python', 'rust'])
                   If None, searches all supported file types
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - symbol: The symbol that was searched for
        - references: Array of reference objects containing:
                    * file_path: Full path to the file containing the reference
                    * file_name: Name of the file
                    * relative_path: Path relative to base directory
                    * line_number: Line number where reference was found (1-based)
                    * column_number: Column position of reference start (1-based)
                    * matched_text: The actual text that matched the symbol
                    * context_line: The complete line containing the reference
                    * reference_type: Type of reference (function_call, variable_usage, etc.)
                    * file_metadata: Basic file information (size, language, etc.)
        - summary: Search statistics including:
                  * total_files_searched: Number of files that were searched
                  * total_files_skipped: Number of files skipped (binary, encoding errors, etc.)
                  * total_references: Total number of references found across all files
                  * files_with_references: Number of files that contained at least one reference
                  * references_by_language: Breakdown of references by programming language
        - error: Error message if operation failed
        
    Example:
        # Find all references to a function
        find_cross_references("login", file_types=["python", "javascript"])
        
        # Find all references to a variable
        find_cross_references("SECRET_KEY", file_types=["python"])
        
        # Find all references to a class
        find_cross_references("UserManager", file_types=["rust"])
    """
    import re
    import time
    
    start_time = time.time()
    
    # Flexible parameter handling for LLM compatibility
    if file_types is None:
        file_types = []
    elif isinstance(file_types, dict):
        # Handle case where LLM passes empty dict or other dict
        file_types = []
    elif isinstance(file_types, str):
        # Handle case where LLM passes single string
        file_types = [file_types]
    elif not isinstance(file_types, list):
        # Handle any other unexpected types
        file_types = []
    
    # Validate file types
    for file_type in file_types:
        if file_type.lower() not in LANGUAGES:
            return json.dumps({
                "success": False,
                "error": f"Unsupported file type: {file_type}. Supported types: {', '.join(LANGUAGES.keys())}",
                "symbol": symbol,
                "references": [],
                "summary": {}
            }, indent=2)
    
    if not symbol.strip():
        return json.dumps({
            "success": False,
            "error": "Symbol cannot be empty",
            "symbol": symbol,
            "references": [],
            "summary": {}
        }, indent=2)
    
    # Use base directory for search
    global BASE_DIRECTORY
    if BASE_DIRECTORY is None:
        return json.dumps({
            "success": False,
            "error": "Base directory not set",
            "symbol": symbol,
            "references": [],
            "summary": {}
        }, indent=2)
    
    try:
        # Create a more precise search pattern for symbol references
        # This looks for word boundaries to avoid partial matches
        escaped_symbol = re.escape(symbol)
        search_pattern = re.compile(r'\b' + escaped_symbol + r'\b', re.IGNORECASE)
        
        references = []
        summary = {
            "total_files_searched": 0,
            "total_files_skipped": 0,
            "total_references": 0,
            "files_with_references": 0,
            "references_by_language": {},
            "search_time_ms": 0,
            "skipped_reasons": {
                "binary_files": 0,
                "encoding_errors": 0,
                "permission_denied": 0,
                "unsupported_language": 0
            }
        }
        
        # Walk through directory tree
        for root, dirs, files in os.walk(BASE_DIRECTORY):
            # Calculate depth
            depth = len(Path(root).relative_to(BASE_DIRECTORY).parts)
            
            # Check depth limit (hardcoded to 20)
            if depth > 20:
                dirs[:] = []  # Don't go deeper
                continue
            
            for filename in files:
                file_path = Path(root) / filename
                
                # Get file metadata
                metadata = get_file_metadata(file_path)
                file_language = metadata.get("language")
                
                # Apply language filter
                if file_types and file_language not in file_types:
                    summary["total_files_skipped"] += 1
                    summary["skipped_reasons"]["unsupported_language"] += 1
                    continue
                
                # Skip binary files
                if is_binary_file(file_path):
                    summary["total_files_skipped"] += 1
                    summary["skipped_reasons"]["binary_files"] += 1
                    continue
                
                # Search within the file
                try:
                    file_references = search_symbol_references(file_path, search_pattern, symbol)
                    
                    if file_references:
                        # Add file metadata to each reference
                        relative_path = get_relative_path(file_path)
                        
                        for ref in file_references:
                            ref.update({
                                "file_path": str(file_path),
                                "file_name": filename,
                                "relative_path": relative_path,
                                "file_metadata": metadata
                            })
                        
                        references.extend(file_references)
                        summary["files_with_references"] += 1
                        summary["total_references"] += len(file_references)
                        
                        # Count by language
                        if file_language:
                            summary["references_by_language"][file_language] = summary["references_by_language"].get(file_language, 0) + len(file_references)
                    
                    summary["total_files_searched"] += 1
                    
                except UnicodeDecodeError:
                    summary["total_files_skipped"] += 1
                    summary["skipped_reasons"]["encoding_errors"] += 1
                    continue
                except PermissionError:
                    summary["total_files_skipped"] += 1
                    summary["skipped_reasons"]["permission_denied"] += 1
                    continue
        
        # Calculate search time
        end_time = time.time()
        summary["search_time_ms"] = round((end_time - start_time) * 1000, 2)
        
        result = {
            "success": True,
            "symbol": symbol,
            "references": references,
            "summary": summary,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except (TypeError, ValueError, AttributeError) as e:
        # Handle parameter validation errors gracefully
        error_msg = f"Parameter validation error: {str(e)}. Using default parameters."
        return json.dumps({
            "success": False,
            "error": error_msg,
            "symbol": symbol,
            "references": [],
            "summary": {"total_files_searched": 0, "total_references": 0}
        }, indent=2)
        
    except Exception as e:
        error_msg = f"Error finding cross-references for '{symbol}': {str(e)}"
        return json.dumps({
            "success": False,
            "error": error_msg,
            "symbol": symbol,
            "references": [],
            "summary": {}
        }, indent=2)


def search_symbol_references(file_path: Path, search_pattern, symbol: str) -> List[dict]:
    """
    Search for symbol references within a single file with context analysis.
    
    Args:
        file_path: Path to the file to search
        search_pattern: Compiled regex pattern to search for
        symbol: The symbol being searched for (for context analysis)
        
    Returns:
        List of reference dictionaries with line numbers, content, and reference type
    """
    references = []
    max_references = 20  # Allow more references for cross-reference analysis
    
    try:
        # Try UTF-8 first, then fallback to other encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        content_lines = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content_lines = f.readlines()
                break
            except UnicodeDecodeError:
                continue
        
        if content_lines is None:
            return references
        
        # Search through each line
        for line_num, line in enumerate(content_lines, 1):
            if len(references) >= max_references:
                break
            
            # Find all matches in this line
            for match in search_pattern.finditer(line):
                if len(references) >= max_references:
                    break
                
                # Analyze context to determine reference type
                context_line = line.rstrip('\n\r')
                matched_text = match.group()
                reference_type = analyze_reference_type(context_line, matched_text, symbol)
                
                reference_info = {
                    "line_number": line_num,
                    "column_number": match.start() + 1,
                    "matched_text": matched_text,
                    "context_line": context_line,
                    "reference_type": reference_type
                }
                
                references.append(reference_info)
        
        return references
        
    except Exception:
        return references


def analyze_reference_type(context_line: str, matched_text: str, symbol: str) -> str:
    """
    Analyze the context to determine the type of reference.
    
    Args:
        context_line: The complete line containing the match
        matched_text: The text that matched the symbol
        symbol: The original symbol being searched for
        
    Returns:
        String describing the type of reference
    """
    context_lower = context_line.lower()
    matched_lower = matched_text.lower()
    
    # Function call patterns
    if '(' in context_line and context_line.find('(') > context_line.find(matched_text):
        return "function_call"
    
    # Variable assignment
    if '=' in context_line and context_line.find('=') > context_line.find(matched_text):
        return "variable_assignment"
    
    # Import statements
    if any(keyword in context_lower for keyword in ['import', 'from', 'use', 'extern']):
        return "import_reference"
    
    # Class definition
    if any(keyword in context_lower for keyword in ['class', 'struct', 'enum', 'trait']):
        return "definition"
    
    # Function definition
    if any(keyword in context_lower for keyword in ['def', 'fn', 'function', 'pub fn']):
        return "function_definition"
    
    # Return statement
    if 'return' in context_lower:
        return "return_value"
    
    # Conditional statements
    if any(keyword in context_lower for keyword in ['if', 'while', 'for', 'switch', 'case']):
        return "conditional_reference"
    
    # Try-catch or error handling
    if any(keyword in context_lower for keyword in ['try', 'catch', 'except', 'throw', 'raise']):
        return "error_handling"
    
    # Comments
    if context_line.strip().startswith(('#', '//', '/*', '*', '--')):
        return "comment_reference"
    
    # Default to variable usage
    return "variable_usage"


def is_binary_file(file_path: Path) -> bool:
    """
    Check if a file is binary by examining its content.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file appears to be binary, False otherwise
    """
    try:
        # Check file extension first for common binary types
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.zip', '.tar', '.gz', '.rar',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.mp3', '.wav', '.mp4', '.avi', '.mov', '.pdf', '.doc', '.docx',
            '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'
        }
        
        if file_path.suffix.lower() in binary_extensions:
            return True
        
        # Sample the first 8192 bytes to check for null bytes
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' in chunk:
                return True
        
        return False
        
    except (OSError, PermissionError):
        return True  # Assume binary if we can't read it





@app.tool(
    description="Get information about the base directory and security restrictions. "
               "This tool helps AI agents understand the working scope and security "
               "boundaries of the filesystem server.",
    title="Get Base Directory Info",
    annotations={}
)
async def get_base_directory_info() -> str:
    """
    Get information about the base directory and security restrictions.
    
    This function provides AI agents with information about the base directory
    that the server is restricted to, helping them understand the working scope
    and security boundaries.
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - base_directory: Path to the base directory
        - base_directory_exists: Whether the base directory exists
        - security_info: Information about security restrictions
        - error: Error message if operation failed
        
    Example:
        >>> get_base_directory_info()
        '{"success": true, "base_directory": "/path/to/project", "security_info": {...}}'
    """
    global BASE_DIRECTORY
    
    try:
        if BASE_DIRECTORY is None:
            return json.dumps({
                "success": False,
                "base_directory": None,
                "base_directory_exists": False,
                "security_info": {
                    "restricted_to_base": True,
                    "description": "All file operations are restricted to the base directory for security"
                },
                "error": "Base directory not set"
            }, indent=2)
        
        # Check if base directory still exists and is accessible
        base_exists = BASE_DIRECTORY.exists() and BASE_DIRECTORY.is_dir()
        
        security_info = {
            "restricted_to_base": True,
            "description": "All file operations are restricted to the base directory for security",
            "path_resolution": "Relative paths are resolved relative to the base directory",
            "security_checks": "All paths are validated to ensure they are within the base directory",
            "prevention": "Prevents access to system files and other projects outside the scope"
        }
        
        result = {
            "success": True,
            "base_directory": str(BASE_DIRECTORY),
            "base_directory_exists": base_exists,
            "security_info": security_info,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_msg = f"Error getting base directory info: {str(e)}"
        return json.dumps({
            "success": False,
            "base_directory": str(BASE_DIRECTORY) if BASE_DIRECTORY else None,
            "base_directory_exists": False,
            "security_info": {},
            "error": error_msg
        }, indent=2)


async def main():
    """
    Main function to run the focused code audit file explorer MCP server.
    
    This server provides code auditor agents with focused file system operations
    including intelligent language detection, directory exploration, and metadata
    extraction for effective code analysis and security auditing.
    
    The server is restricted to operate only within the specified base directory
    for security purposes and focuses on file exploration rather than content search.
    """
    try:
        await app.run()
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        pass
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        # Check command line arguments
        if len(sys.argv) != 2:
            print("Usage: python file_system_tools.py <base_directory>", file=sys.stderr)
            print("Example: python file_system_tools.py /path/to/project", file=sys.stderr)
            sys.exit(1)
        
        base_directory = sys.argv[1]
        
        # Set the base directory (this will exit if invalid)
        set_base_directory(base_directory)
        
        # Set Windows event loop policy to prevent pipe warnings
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Suppress asyncio warnings
        import logging
        logging.getLogger('asyncio').setLevel(logging.WARNING)
        
        # Run the focused file explorer MCP server
        app.run()
            
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("Received KeyboardInterrupt, shutting down gracefully", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)