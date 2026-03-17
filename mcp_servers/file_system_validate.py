#!/usr/bin/env python3
"""
MCP Vulnerability Validation Filesystem Server

A streamlined filesystem server designed specifically for AI agents performing vulnerability validation and false positive detection.
This server provides focused file operations optimized for security analysis workflows.

IMPORTANT SECURITY FEATURE:
- All file operations are restricted to a base directory specified at startup
- The server will never access files outside the designated base directory
- This prevents AI agents from accessing sensitive system files or other projects

Key Features:
- Fast file reading with security context
- Vulnerability-focused metadata extraction
- Language detection for security analysis
- Structured output optimized for validation workflows
- Comprehensive error handling for robust automation
- Security: Restricted to base directory only

Usage for Vulnerability Validation:
1. Use read_file() to examine vulnerable code sections
2. Use get_file_context() to understand surrounding code
3. Use analyze_security_context() for vulnerability-specific analysis
4. Use validate_file_access() to check file permissions and existence

Command Line Usage:
    python file_system_validate.py <base_directory>
    
Example:
    python file_system_validate.py /path/to/project
"""

import asyncio
import json
import os
import sys
import re
import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from mcp.server import FastMCP

# Security-focused language definitions
SECURITY_LANGUAGES = {
    'solidity': {
        'extensions': ['.sol'],
        'description': 'Solidity smart contract files',
        'security_patterns': ['reentrancy', 'overflow', 'access_control', 'external_calls']
    },
    'rust': {
        'extensions': ['.rs'],
        'description': 'Rust programming language files',
        'security_patterns': ['unsafe', 'memory_safety', 'panic', 'unwrap']
    },
    'python': {
        'extensions': ['.py', '.pyw', '.pyi'],
        'description': 'Python programming language files',
        'security_patterns': ['eval', 'exec', 'pickle', 'subprocess', 'os.system']
    },
    'javascript': {
        'extensions': ['.js', '.mjs', '.cjs'],
        'description': 'JavaScript programming language files',
        'security_patterns': ['eval', 'innerHTML', 'document.write', 'setTimeout']
    },
    'typescript': {
        'extensions': ['.ts', '.tsx'],
        'description': 'TypeScript programming language files',
        'security_patterns': ['eval', 'innerHTML', 'document.write', 'setTimeout']
    },
    'c': {
        'extensions': ['.c', '.h'],
        'description': 'C programming language files',
        'security_patterns': ['strcpy', 'sprintf', 'gets', 'scanf', 'malloc']
    },
    'cpp': {
        'extensions': ['.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hxx', '.h++'],
        'description': 'C++ programming language files',
        'security_patterns': ['strcpy', 'sprintf', 'gets', 'scanf', 'new', 'delete']
    },
    'go': {
        'extensions': ['.go'],
        'description': 'Go programming language files',
        'security_patterns': ['unsafe', 'reflect', 'cgo', 'syscall']
    },
    'java': {
        'extensions': ['.java'],
        'description': 'Java programming language files',
        'security_patterns': ['Runtime.exec', 'ProcessBuilder', 'Class.forName', 'Reflection']
    }
}

# Global base directory - set at startup
BASE_DIRECTORY: Optional[Path] = None

# Create FastMCP server instance
app = FastMCP("vulnerability-validate-filesystem-server")


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
        except PermissionError as exc:
            raise ValueError(f"Permission denied accessing base directory: {base_dir}") from exc
        
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


def normalize_file_patterns(file_patterns: Any) -> Optional[List[str]]:
    """
    Normalize file_patterns input from various formats into a list of strings.
    
    Accepts:
    - List: ['*.py', '*.js']
    - Single string: '*.py'
    - Dict with 'include': {'include': ['*.py']}
    - Dict with 'exclude': {'exclude': ['*.test.py']}
    - None: returns None
    
    Args:
        file_patterns: File patterns in various formats
        
    Returns:
        List of file patterns or None
    """
    if file_patterns is None:
        return None
    
    # Handle dict format
    if isinstance(file_patterns, dict):
        if 'include' in file_patterns:
            include = file_patterns['include']
            if isinstance(include, list):
                return include
            elif isinstance(include, str):
                return [include]
            else:
                return None
        elif 'exclude' in file_patterns:
            # For exclude, we still need to return patterns to search
            # The caller should handle exclusion logic if needed
            exclude = file_patterns['exclude']
            if isinstance(exclude, list):
                # Return all common patterns and let filtering happen
                return None  # Will default to search all files
            else:
                return None
        else:
            return None
    
    # Handle list
    if isinstance(file_patterns, list):
        return file_patterns
    
    # Handle single string
    if isinstance(file_patterns, str):
        return [file_patterns]
    
    # Unknown format
    return None


def get_language_from_extension(file_path: Path) -> Optional[str]:
    """
    Detect programming language from file extension for security analysis.
    
    Args:
        file_path: Path object representing the file
        
    Returns:
        Language name (e.g., 'python', 'solidity') or None if not recognized
    """
    suffix = file_path.suffix.lower()
    for lang, lang_info in SECURITY_LANGUAGES.items():
        if suffix in lang_info['extensions']:
            return lang
    return None


def get_security_metadata(file_path: Path) -> Dict[str, Any]:
    """
    Get security-focused metadata about a file.
    
    Args:
        file_path: Path object representing the file
        
    Returns:
        Dictionary containing security-relevant file metadata
    """
    try:
        stat = file_path.stat()
        language = get_language_from_extension(file_path)
        
        return {
            'name': file_path.name,
            'size': stat.st_size,
            'language': language,
            'extension': file_path.suffix.lower(),
            'is_hidden': file_path.name.startswith('.'),
            'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'is_file': file_path.is_file(),
            'is_directory': file_path.is_dir(),
            'security_patterns': SECURITY_LANGUAGES.get(language, {}).get('security_patterns', []),
            'relative_path': get_relative_path(file_path)
        }
    except (OSError, IOError) as e:
        return {
            'name': file_path.name,
            'error': f"Could not read metadata: {str(e)}",
            'is_hidden': file_path.name.startswith('.'),
            'relative_path': get_relative_path(file_path)
        }


@app.tool(
    description="Get intelligent search suggestions for finding vulnerable code patterns. "
                "Helps LLM models understand what patterns to search for based on the project structure and security goals. "
                "Provides pattern examples, common vulnerabilities by language, and recommended file patterns.",
    title="Get Search Suggestions",
    annotations={
        "target_language": "Programming language to focus on (e.g., 'python', 'solidity', 'rust') - optional",
        "vulnerability_type": "Type of vulnerability to search for (e.g., 'injection', 'crypto', 'reentrancy') - optional"
    }
)
async def get_search_suggestions(
    target_language: Optional[str] = None,
    vulnerability_type: Optional[str] = None
) -> str:
    """
    Get intelligent search suggestions for finding vulnerable code patterns.
    
    This tool helps LLM models understand what patterns to search for based on
    the project structure, programming languages, and security goals.
    
    Args:
        target_language: Programming language to focus on (optional)
        vulnerability_type: Type of vulnerability to search for (optional)
    
    Returns:
        JSON string containing:
        - suggested_patterns: Code patterns to search for
        - vulnerability_patterns: Language-specific vulnerability patterns
        - file_patterns: Recommended file patterns by language
        - search_examples: Example search queries
        - success: Boolean indicating if operation was successful
        - error: Error message if operation failed
        
    Example:
        >>> get_search_suggestions(target_language='python', vulnerability_type='injection')
        '{"success": true, "suggested_patterns": [...], "search_examples": [...]}'
    """
    try:
        # Common vulnerability patterns by language
        vulnerability_patterns_by_lang = {
            'python': {
                'injection': ['eval(', 'exec(', 'os.system', 'subprocess.call', '__import__', 'compile('],
                'crypto': ['hashlib.md5', 'hashlib.sha1', 'DES.', '3DES.', 'RC4'],
                'pickle': ['pickle.load', 'pickle.dumps', 'pickle.loads'],
                'xss': ['render_template_string', 'Markup(', 'escape=False']
            },
            'javascript': {
                'injection': ['eval(', 'Function(', 'setTimeout', 'setInterval'],
                'xss': ['innerHTML', 'document.write', '$.html(', 'dangerouslySetInnerHTML'],
                'crypto': ['crypto.createHash', 'md5(', 'sha1(']
            },
            'solidity': {
                'reentrancy': ['call(', 'send(', 'transfer(', '.call.value'],
                'overflow': ['+=', '-=', '*=', '/='],
                'unchecked': ['unchecked', '++', '--'],
                'access_control': ['require(', 'assert(', 'modifier']
            },
            'rust': {
                'unsafe': ['unsafe {', 'unsafe fn', 'unsafe impl'],
                'panic': ['.unwrap(', '.expect(', 'panic!', 'unreachable!'],
                'overflow': ['wrapping_add', 'wrapping_sub']
            },
            'go': {
                'injection': ['exec.Command', 'os.Exec', 'syscall'],
                'crypto': ['crypto/md5', 'crypto/sha1']
            },
            'c': {
                'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'],
                'use_after_free': ['malloc', 'free', 'realloc']
            },
            'cpp': {
                'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'gets'],
                'memory_leak': ['new', 'delete', 'malloc', 'free']
            }
        }
        
        # File patterns by language
        file_patterns_by_lang = {
            'python': ['*.py'],
            'javascript': ['*.js', '*.mjs', '*.cjs'],
            'typescript': ['*.ts', '*.tsx'],
            'solidity': ['*.sol'],
            'rust': ['*.rs'],
            'go': ['*.go'],
            'java': ['*.java'],
            'c': ['*.c', '*.h'],
            'cpp': ['*.cpp', '*.hpp', '*.cc', '*.cxx', '*.h']
        }
        
        # Build suggestions
        suggested_patterns = {}
        vulnerability_patterns = {}
        search_examples = []
        
        if target_language and target_language in vulnerability_patterns_by_lang:
            lang_vulns = vulnerability_patterns_by_lang[target_language]
            
            # Filter by vulnerability type if specified
            if vulnerability_type and vulnerability_type in lang_vulns:
                suggested_patterns[vulnerability_type] = lang_vulns[vulnerability_type]
            else:
                suggested_patterns = lang_vulns
            
            # Add file patterns
            if target_language in file_patterns_by_lang:
                search_examples.append({
                    "description": f"Search for vulnerabilities in {target_language} files",
                    "pattern": "vulnerable_pattern",
                    "file_patterns": file_patterns_by_lang[target_language],
                    "example": f"search_code_patterns('unsafe', {file_patterns_by_lang[target_language]})"
                })
        
        else:
            # Provide suggestions for all languages
            for lang, vulns in vulnerability_patterns_by_lang.items():
                vulnerability_patterns[lang] = vulns
                if lang in file_patterns_by_lang:
                    search_examples.append({
                        "language": lang,
                        "file_patterns": file_patterns_by_lang[lang],
                        "vulnerabilities": list(vulns.keys())
                    })
        
        result = {
            "success": True,
            "suggested_patterns": suggested_patterns,
            "vulnerability_patterns": vulnerability_patterns,
            "file_patterns": file_patterns_by_lang,
            "search_examples": search_examples,
            "tip": "Use discover_project_files() first to understand project structure, then use search_code_patterns() with appropriate patterns",
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "suggested_patterns": {},
            "vulnerability_patterns": {},
            "file_patterns": {},
            "search_examples": [],
            "error": f"Error getting search suggestions: {str(e)}"
        }, indent=2)


@app.tool(
    description="Read file contents for vulnerability validation and security analysis. "
                "Optimized for security validation workflows with focused metadata. "
                "Handles encoding errors and provides security context for analysis.",
    title="Read File for Validation",
    annotations={
        "path": "Absolute or relative path to the file to read. Must be within the project base directory.",
        "encoding": "File encoding (default: utf-8). Try 'latin-1' or 'cp1252' if you encounter decode errors."
    }
)
async def read_file(
    path: str,
    encoding: str = "utf-8"
) -> str:
    """
    Read file contents optimized for vulnerability validation.

    This tool is specifically designed for security validation agents to read files
    during vulnerability analysis. It provides security-focused metadata and handles
    common encoding issues encountered in real-world codebases.

    Args:
        path: Path to the file to read (absolute or relative to base directory)
        encoding: File encoding (default: utf-8). Try 'latin-1' or 'cp1252' if utf-8 fails.

    Returns:
        JSON string with:
            - content: File contents as string
            - metadata: Security-focused file info
            - success: True if read succeeded, False otherwise
            - error: Error message if any

    Example:
        >>> read_file("src/vulnerable_function.py")
        '{"success": true, "content": "...", "metadata": {...}, "error": null}'
    """
    is_valid, error_msg, file_path = validate_path_within_base(path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "error": error_msg,
            "content": "",
            "metadata": {}
        }, indent=2)

    if not file_path.is_file():
        return json.dumps({
            "success": False,
            "error": f"Path is not a file: {path}",
            "content": "",
            "metadata": get_security_metadata(file_path)
        }, indent=2)

    try:
        with open(file_path, 'r', encoding=encoding) as f:
            content = f.read()

        metadata = get_security_metadata(file_path)
        metadata.update({
            "encoding_used": encoding,
            "content_length": len(content),
            "line_count": len(content.splitlines()) if content else 0
        })

        return json.dumps({
            "success": True,
            "content": content,
            "metadata": metadata,
            "error": None
        }, indent=2)

    except UnicodeDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Could not decode file with encoding '{encoding}': {str(e)}. Try 'latin-1' or 'cp1252'.",
            "content": "",
            "metadata": get_security_metadata(file_path)
        }, indent=2)

    except PermissionError as e:
        return json.dumps({
            "success": False,
            "error": f"Permission denied reading file '{path}': {str(e)}",
            "content": "",
            "metadata": get_security_metadata(file_path)
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"Unexpected error reading file '{path}': {str(e)}",
            "content": "",
            "metadata": get_security_metadata(file_path)
        }, indent=2)


@app.tool(
    description="Get security-focused file metadata without reading content. "
                "Useful for quick vulnerability assessment and file prioritization.",
    title="Get Security Metadata",
    annotations={
        "path": "Absolute or relative path to the file"
    }
)
async def get_security_metadata_tool(path: str) -> str:
    """
    Get security-focused metadata about a file without reading its content.
    
    This function provides vulnerability validation agents with file information
    optimized for security analysis, including language-specific security patterns
    and file characteristics relevant to vulnerability assessment.
    
    Args:
        path: Path to the file to get metadata for
        
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - metadata: Security-focused file metadata dictionary
        - error: Error message if operation failed
        
    Example:
        >>> get_security_metadata_tool("/path/to/contract.sol")
        '{"success": true, "metadata": {"name": "contract.sol", "language": "solidity", "security_patterns": [...]}}'
    """
    is_valid, error_msg, file_path = validate_path_within_base(path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "metadata": {},
            "error": error_msg
        }, indent=2)
    
    if not file_path.is_file():
        return json.dumps({
            "success": False,
            "metadata": get_security_metadata(file_path),
            "error": f"Path is not a file: {path}"
        }, indent=2)
    
    try:
        metadata = get_security_metadata(file_path)
        
        result = {
            "success": True,
            "metadata": metadata,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_msg = f"Error getting security metadata for '{path}': {str(e)}"
        return json.dumps({
            "success": False,
            "metadata": {},
            "error": error_msg
        }, indent=2)


@app.tool(
    description="Read file with surrounding context for vulnerability analysis. "
                "Provides the target file plus related files that might contain security controls or context.",
    title="Read File with Context",
    annotations={
        "path": "Path to the main file to analyze",
        "context_files": "List of related file paths to include for context (optional)",
        "encoding": "File encoding (default: utf-8)"
    }
)
async def read_file_with_context(
    path: str,
    context_files: Optional[List[str]] = None,
    encoding: str = "utf-8"
) -> str:
    """
    Read a file along with its security context for comprehensive vulnerability analysis.
    
    This tool reads the main file and optionally includes related files that might
    contain security controls, configurations, or context relevant to vulnerability analysis.
    
    Args:
        path: Path to the main file to analyze
        context_files: Optional list of related file paths to include
        encoding: File encoding (default: utf-8)
    
    Returns:
        JSON string containing:
        - main_file: Main file content and metadata
        - context_files: Array of related file contents and metadata
        - success: Boolean indicating if operation was successful
        - error: Error message if operation failed
        
    Example:
        >>> read_file_with_context("src/auth.py", ["src/config.py", "src/utils.py"])
        '{"success": true, "main_file": {...}, "context_files": [...]}'
    """
    if context_files is None:
        context_files = []
    
    # Read main file
    main_file_result = await read_file(path, encoding)
    main_file_data = json.loads(main_file_result)
    
    if not main_file_data["success"]:
        return main_file_result
    
    # Read context files
    context_files_data = []
    for context_path in context_files:
        context_result = await read_file(context_path, encoding)
        context_data = json.loads(context_result)
        context_files_data.append({
            "path": context_path,
            "success": context_data["success"],
            "content": context_data.get("content", ""),
            "metadata": context_data.get("metadata", {}),
            "error": context_data.get("error")
        })
    
    result = {
        "success": True,
        "main_file": {
            "path": path,
            "content": main_file_data["content"],
            "metadata": main_file_data["metadata"]
        },
        "context_files": context_files_data,
        "error": None
    }
    
    return json.dumps(result, indent=2)


@app.tool(
    description="Get information about the base directory and security restrictions. "
                "Helps understand the working scope for vulnerability validation.",
    title="Get Base Directory Info",
    annotations={}
)
async def get_base_directory_info() -> str:
    """
    Get information about the base directory and security restrictions.
    
    This function provides vulnerability validation agents with information about
    the base directory scope and security boundaries for their analysis.
    
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
            "prevention": "Prevents access to system files and other projects outside the scope",
            "supported_languages": list(SECURITY_LANGUAGES.keys())
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


@app.tool(
    description="Search for specific patterns or code snippets across files. "
                "Useful for finding vulnerable code patterns, security functions, or specific implementations. "
                "Supports regex patterns and case-sensitive/insensitive matching. "
                "Accepts flexible file_patterns: list ['*.py', '*.js'], single string '*.py', or dict {'include': ['*.py']}.",
    title="Search Code Patterns",
    annotations={
        "pattern": "Regex pattern or simple text to search for",
        "file_patterns": "File patterns to search in. Accepts: list ['*.py'], single string '*.py', or dict {'include': ['*.py']}. Common patterns: ['*.py', '*.js', '*.sol', '*.ts', '*.rs', '*.go', '*.java', '*.cpp', '*.c']",
        "case_sensitive": "Whether search should be case sensitive (default: False)",
        "max_files": "Maximum number of files to search (default: 50)"
    }
)
async def search_code_patterns(
    pattern: str,
    file_patterns: Optional[Any] = None,
    case_sensitive: bool = False,
    max_files: int = 50
) -> str:
    """
    Search for specific patterns or code snippets across files.
    
    This tool helps vulnerability validation agents quickly find specific code patterns,
    vulnerable functions, or security-related implementations without reading entire files.
    
    Flexible Input Support:
    - List: ['*.py', '*.js'] - searches Python and JavaScript files
    - Single string: '*.py' - searches only Python files
    - Dict with 'include': {'include': ['*.py', '*.js']} - searches specified files
    - Dict with 'exclude': {'exclude': ['*.test.py']} - excludes test files
    - None: searches all files
    
    Args:
        pattern: Regex pattern or simple text to search for
        file_patterns: File patterns to search in. Accepts multiple formats:
            - List: ['*.py', '*.js'] 
            - Single string: '*.py'
            - Dict: {'include': ['*.py']} or {'exclude': ['*.test.py']}
            - None: searches all files
        case_sensitive: Whether search should be case sensitive
        max_files: Maximum number of files to search to prevent overwhelming results
    
    Returns:
        JSON string containing:
        - matches: Array of matches with file path, line number, and context
        - summary: Search statistics
        - success: Boolean indicating if operation was successful
        - error: Error message if operation failed
        - suggestions: Helpful suggestions if no matches found
        
    Example:
        >>> search_code_patterns("eval\\(", ["*.py", "*.js"])
        '{"success": true, "matches": [...], "summary": {...}}'
        >>> search_code_patterns("unsafe", '*.rs')
        '{"success": true, "matches": [...], "summary": {...}}'
        >>> search_code_patterns("reentrancy", {'include': ['*.sol']})
        '{"success": true, "matches": [...], "summary": {...}}'
    """
    # Normalize file_patterns to a consistent format
    normalized_patterns = normalize_file_patterns(file_patterns)
    
    if normalized_patterns is None or len(normalized_patterns) == 0:
        file_patterns_list = ['*']  # Search all files
    else:
        file_patterns_list = normalized_patterns
    
    global BASE_DIRECTORY
    if BASE_DIRECTORY is None:
        return json.dumps({
            "success": False,
            "matches": [],
            "summary": {},
            "error": "Base directory not set"
        }, indent=2)
    
    try:
        matches = []
        files_searched = 0
        total_matches = 0
        
        # Compile regex pattern
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            compiled_pattern = re.compile(pattern, flags)
        except re.error as e:
            return json.dumps({
                "success": False,
                "matches": [],
                "summary": {},
                "error": f"Invalid regex pattern: {str(e)}"
            }, indent=2)
        
        # Search through files
        for root, _, files in os.walk(BASE_DIRECTORY):
            if files_searched >= max_files:
                break
                
            for filename in files:
                if files_searched >= max_files:
                    break
                    
                # Check if file matches any pattern
                file_matches_pattern = False
                for file_pattern in file_patterns_list:
                    if fnmatch.fnmatch(filename, file_pattern):
                        file_matches_pattern = True
                        break
                
                if not file_matches_pattern:
                    continue
                
                file_path = Path(root) / filename
                files_searched += 1
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        if compiled_pattern.search(line):
                            # Get context lines (2 before and after)
                            start_line = max(1, line_num - 2)
                            end_line = min(len(lines), line_num + 3)
                            context_lines = lines[start_line-1:end_line]
                            
                            match_data = {
                                "file_path": str(file_path),
                                "relative_path": get_relative_path(file_path),
                                "line_number": line_num,
                                "line_content": line.strip(),
                                "context": {
                                    "start_line": start_line,
                                    "end_line": end_line,
                                    "lines": [l.strip() for l in context_lines]
                                },
                                "language": get_language_from_extension(file_path)
                            }
                            matches.append(match_data)
                            total_matches += 1
                            
                except Exception:
                    # Skip files that can't be read
                    continue
        
        summary = {
            "pattern": pattern,
            "file_patterns": file_patterns_list,
            "files_searched": files_searched,
            "total_matches": total_matches,
            "case_sensitive": case_sensitive,
            "max_files_limit": max_files
        }
        
        # Add suggestions if no matches found
        suggestions = None
        if total_matches == 0 and files_searched == 0:
            # Find what file types exist
            unique_extensions = set()
            for root, _, files in os.walk(BASE_DIRECTORY):
                for filename in files[:100]:  # Sample first 100 files
                    ext = Path(filename).suffix.lower()
                    if ext and ext != '.':  # Filter out files without extensions
                        unique_extensions.add(ext)
                    else:
                        unique_extensions.add('(no extension)')
                    if len(unique_extensions) >= 10:  # Limit to 10 samples
                        break
                if len(unique_extensions) >= 10:
                    break
            
            suggestions = {
                "message": "No files matched the search criteria. Try these patterns:",
                "available_files_sample": list(unique_extensions),
                "suggested_patterns": {
                    "python": "['*.py']",
                    "javascript": "['*.js', '*.mjs', '*.cjs']",
                    "typescript": "['*.ts', '*.tsx']",
                    "solidity": "['*.sol']",
                    "rust": "['*.rs']",
                    "go": "['*.go']",
                    "java": "['*.java']",
                    "c_cpp": "['*.c', '*.cpp', '*.h', '*.hpp']",
                    "all": "['*']"
                },
                "hint": f"Try: search_code_patterns('{pattern}', ['*']) to search all files"
            }
        
        result = {
            "success": True,
            "matches": matches,
            "summary": summary,
            "suggestions": suggestions,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "matches": [],
            "summary": {},
            "suggestions": None,
            "error": f"Error searching code patterns: {str(e)}"
        }, indent=2)


@app.tool(
    description="Discover available files in the project directory. "
                "Helps LLM models understand what files are available before searching. "
                "Returns file types, extensions, and directory structure.",
    title="Discover Project Files",
    annotations={
        "max_files": "Maximum number of files to return (default: 100)",
        "file_patterns": "Filter by file patterns (e.g., ['*.py', '*.js']) - optional",
        "include_hidden": "Whether to include hidden files (default: False)"
    }
)
async def discover_project_files(
    max_files: int = 100,
    file_patterns: Optional[Any] = None,
    include_hidden: bool = False
) -> str:
    """
    Discover available files in the project directory.
    
    This tool helps LLM models understand what files are available in the project
    before performing searches or analysis. It provides a directory structure overview
    and file type statistics.
    
    Args:
        max_files: Maximum number of files to return
        file_patterns: Filter by file patterns (optional). Accepts list, string, or dict
        include_hidden: Whether to include hidden files
    
    Returns:
        JSON string containing:
        - files: Array of file information
        - statistics: File type and directory statistics
        - directory_structure: Directory tree overview
        - suggested_patterns: Suggested file patterns for common languages
        - success: Boolean indicating if operation was successful
        - error: Error message if operation failed
        
    Example:
        >>> discover_project_files(max_files=50)
        '{"success": true, "files": [...], "statistics": {...}, "directory_structure": {...}}'
    """
    global BASE_DIRECTORY
    
    if BASE_DIRECTORY is None:
        return json.dumps({
            "success": False,
            "files": [],
            "statistics": {},
            "directory_structure": {},
            "suggested_patterns": {},
            "error": "Base directory not set"
        }, indent=2)
    
    try:
        # Normalize file patterns if provided
        patterns_list = None
        if file_patterns is not None:
            normalized = normalize_file_patterns(file_patterns)
            if normalized:
                patterns_list = normalized
        
        files_data = []
        extensions_count = {}
        directories_set = set()
        languages_count = {}
        
        for root, dirs, files in os.walk(BASE_DIRECTORY):
            if len(files_data) >= max_files:
                break
            
            # Track directories
            rel_root = get_relative_path(Path(root))
            directories_set.add(rel_root)
            
            for filename in files:
                if len(files_data) >= max_files:
                    break
                
                # Skip hidden files if not included
                if not include_hidden and filename.startswith('.'):
                    continue
                
                # Check file pattern filter
                if patterns_list:
                    matches_pattern = False
                    for pattern in patterns_list:
                        if fnmatch.fnmatch(filename, pattern):
                            matches_pattern = True
                            break
                    if not matches_pattern:
                        continue
                
                file_path = Path(root) / filename
                ext = file_path.suffix.lower()
                language = get_language_from_extension(file_path)
                
                # Count statistics
                if ext:
                    extensions_count[ext] = extensions_count.get(ext, 0) + 1
                else:
                    extensions_count['(no extension)'] = extensions_count.get('(no extension)', 0) + 1
                
                if language:
                    languages_count[language] = languages_count.get(language, 0) + 1
                
                files_data.append({
                    "name": filename,
                    "path": str(file_path),
                    "relative_path": get_relative_path(file_path),
                    "extension": ext,
                    "language": language,
                    "size": file_path.stat().st_size if file_path.exists() else 0,
                    "directory": rel_root
                })
        
        # Get most common extensions
        top_extensions = sorted(extensions_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        statistics = {
            "total_files_discovered": len(files_data),
            "unique_extensions": len(extensions_count),
            "top_extensions": top_extensions,
            "languages": languages_count,
            "directories_count": len(directories_set)
        }
        
        # Build directory structure
        directory_structure = {}
        for file_info in files_data:
            dir_path = file_info['directory']
            if dir_path not in directory_structure:
                directory_structure[dir_path] = []
            directory_structure[dir_path].append(file_info['name'])
        
        # Suggested patterns based on discovered files
        suggested_patterns = {}
        if '.py' in extensions_count:
            suggested_patterns['python'] = ['*.py']
        if '.js' in extensions_count or '.mjs' in extensions_count:
            suggested_patterns['javascript'] = ['*.js', '*.mjs', '*.cjs']
        if '.ts' in extensions_count or '.tsx' in extensions_count:
            suggested_patterns['typescript'] = ['*.ts', '*.tsx']
        if '.sol' in extensions_count:
            suggested_patterns['solidity'] = ['*.sol']
        if '.rs' in extensions_count:
            suggested_patterns['rust'] = ['*.rs']
        if '.go' in extensions_count:
            suggested_patterns['go'] = ['*.go']
        if '.java' in extensions_count:
            suggested_patterns['java'] = ['*.java']
        if '.c' in extensions_count or '.cpp' in extensions_count:
            suggested_patterns['c_cpp'] = ['*.c', '*.cpp', '*.h', '*.hpp']
        
        result = {
            "success": True,
            "files": files_data,
            "statistics": statistics,
            "directory_structure": directory_structure,
            "suggested_patterns": suggested_patterns,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "files": [],
            "statistics": {},
            "directory_structure": {},
            "suggested_patterns": {},
            "error": f"Error discovering project files: {str(e)}"
        }, indent=2)


@app.tool(
    description="Extract specific functions, classes, or code blocks from files. "
                "Useful for analyzing specific vulnerable functions or security implementations. "
                "Supports function name matching and line range extraction.",
    title="Extract Code Blocks",
    annotations={
        "file_path": "Path to the file to extract from",
        "function_name": "Name of function/class to extract (optional)",
        "start_line": "Starting line number (optional)",
        "end_line": "Ending line number (optional)",
        "include_comments": "Whether to include comments and docstrings (default: True)"
    }
)
async def extract_code_blocks(
    file_path: str,
    function_name: Optional[str] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
    include_comments: bool = True
) -> str:
    """
    Extract specific functions, classes, or code blocks from files.
    
    This tool helps vulnerability validation agents focus on specific code sections
    without reading entire files, making analysis more efficient.
    
    Args:
        file_path: Path to the file to extract from
        function_name: Name of function/class to extract (optional)
        start_line: Starting line number for range extraction (optional)
        end_line: Ending line number for range extraction (optional)
        include_comments: Whether to include comments and docstrings
    
    Returns:
        JSON string containing:
        - code_blocks: Array of extracted code blocks
        - metadata: File and extraction metadata
        - success: Boolean indicating if operation was successful
        - error: Error message if operation failed
        
    Example:
        >>> extract_code_blocks("src/auth.py", function_name="login")
        '{"success": true, "code_blocks": [...], "metadata": {...}}'
    """
    is_valid, error_msg, file_path_obj = validate_path_within_base(file_path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "code_blocks": [],
            "metadata": {},
            "error": error_msg
        }, indent=2)
    
    if not file_path_obj.is_file():
        return json.dumps({
            "success": False,
            "code_blocks": [],
            "metadata": {},
            "error": f"Path is not a file: {file_path}"
        }, indent=2)
    
    try:
        with open(file_path_obj, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        code_blocks = []
        language = get_language_from_extension(file_path_obj)
        
        if function_name:
            # Search for function/class definition
            function_patterns = {
                'python': [rf'def\s+{re.escape(function_name)}\s*\(', rf'class\s+{re.escape(function_name)}\s*[\(:]'],
                'javascript': [rf'function\s+{re.escape(function_name)}\s*\(', rf'const\s+{re.escape(function_name)}\s*=', rf'let\s+{re.escape(function_name)}\s*='],
                'typescript': [rf'function\s+{re.escape(function_name)}\s*\(', rf'const\s+{re.escape(function_name)}\s*=', rf'class\s+{re.escape(function_name)}\s*[\(<]'],
                'solidity': [rf'function\s+{re.escape(function_name)}\s*\(', rf'contract\s+{re.escape(function_name)}\s*[{{]'],
                'rust': [rf'fn\s+{re.escape(function_name)}\s*\(', rf'struct\s+{re.escape(function_name)}\s*[{{]'],
                'c': [rf'{re.escape(function_name)}\s*\(', rf'struct\s+{re.escape(function_name)}\s*[{{]'],
                'cpp': [rf'{re.escape(function_name)}\s*\(', rf'class\s+{re.escape(function_name)}\s*[{{]'],
                'go': [rf'func\s+{re.escape(function_name)}\s*\(', rf'type\s+{re.escape(function_name)}\s*[{{]'],
                'java': [rf'{re.escape(function_name)}\s*\(', rf'class\s+{re.escape(function_name)}\s*[{{]']
            }
            
            patterns = function_patterns.get(language, [rf'{re.escape(function_name)}\s*\('])
            
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Found function/class definition, extract it
                        block = extract_code_block(lines, line_num, language, include_comments)
                        if block:
                            code_blocks.append(block)
        
        elif start_line and end_line:
            # Extract specific line range
            if 1 <= start_line <= end_line <= len(lines):
                block_lines = lines[start_line-1:end_line]
                code_content = ''.join(block_lines)
                
                code_blocks.append({
                    "type": "line_range",
                    "start_line": start_line,
                    "end_line": end_line,
                    "content": code_content,
                    "line_count": end_line - start_line + 1
                })
        
        else:
            # Extract all functions/classes in the file
            all_blocks = extract_all_code_blocks(lines, language, include_comments)
            code_blocks.extend(all_blocks)
        
        metadata = {
            "file_path": str(file_path_obj),
            "relative_path": get_relative_path(file_path_obj),
            "language": language,
            "total_lines": len(lines),
            "extraction_criteria": {
                "function_name": function_name,
                "start_line": start_line,
                "end_line": end_line,
                "include_comments": include_comments
            }
        }
        
        result = {
            "success": True,
            "code_blocks": code_blocks,
            "metadata": metadata,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "code_blocks": [],
            "metadata": {},
            "error": f"Error extracting code blocks: {str(e)}"
        }, indent=2)


def extract_code_block(lines: List[str], start_line: int, language: str, include_comments: bool = True) -> Optional[Dict[str, Any]]:
    """Extract a complete code block starting from the given line."""
    if start_line < 1 or start_line > len(lines):
        return None
    
    # Language-specific indentation patterns
    indent_patterns = {
        'python': lambda line: len(line) - len(line.lstrip()),
        'javascript': lambda line: len(line) - len(line.lstrip()),
        'typescript': lambda line: len(line) - len(line.lstrip()),
        'solidity': lambda line: len(line) - len(line.lstrip()),
        'rust': lambda line: len(line) - len(line.lstrip()),
        'c': lambda line: len(line) - len(line.lstrip()),
        'cpp': lambda line: len(line) - len(line.lstrip()),
        'go': lambda line: len(line) - len(line.lstrip()),
        'java': lambda line: len(line) - len(line.lstrip())
    }
    
    get_indent = indent_patterns.get(language, lambda line: len(line) - len(line.lstrip()))
    
    start_idx = start_line - 1
    start_line_content = lines[start_idx]
    base_indent = get_indent(start_line_content)
    
    # Find the end of the block
    end_idx = start_idx
    brace_count = 0
    paren_count = 0
    
    for i in range(start_idx, len(lines)):
        line = lines[i]
        
        # Count braces and parentheses for block detection
        brace_count += line.count('{') - line.count('}')
        paren_count += line.count('(') - line.count(')')
        
        # Check for end of block
        if i > start_idx:
            current_indent = get_indent(line)
            if line.strip() and current_indent <= base_indent and brace_count <= 0 and paren_count <= 0:
                end_idx = i
                break
        
        end_idx = i
    
    # Extract the block
    block_lines = lines[start_idx:end_idx+1]
    content = ''.join(block_lines)
    
    return {
        "type": "function_or_class",
        "start_line": start_line,
        "end_line": end_idx + 1,
        "content": content,
        "line_count": end_idx - start_idx + 1,
        "indentation": base_indent
    }


def extract_all_code_blocks(lines: List[str], language: str, include_comments: bool) -> List[Dict[str, Any]]:
    """Extract all functions and classes from the file."""
    blocks = []
    
    # Language-specific patterns for function/class definitions
    patterns = {
        'python': [r'def\s+\w+\s*\(', r'class\s+\w+\s*[\(:]'],
        'javascript': [r'function\s+\w+\s*\(', r'const\s+\w+\s*=', r'let\s+\w+\s*=', r'class\s+\w+\s*[{{]'],
        'typescript': [r'function\s+\w+\s*\(', r'const\s+\w+\s*=', r'class\s+\w+\s*[\(<]'],
        'solidity': [r'function\s+\w+\s*\(', r'contract\s+\w+\s*[{{]'],
        'rust': [r'fn\s+\w+\s*\(', r'struct\s+\w+\s*[{{]'],
        'c': [r'\w+\s*\([^)]*\)\s*[{{]', r'struct\s+\w+\s*[{{]'],
        'cpp': [r'\w+\s*\([^)]*\)\s*[{{]', r'class\s+\w+\s*[{{]'],
        'go': [r'func\s+\w+\s*\(', r'type\s+\w+\s*[{{]'],
        'java': [r'\w+\s*\([^)]*\)\s*[{{]', r'class\s+\w+\s*[{{]']
    }
    
    lang_patterns = patterns.get(language, [r'\w+\s*\([^)]*\)\s*[{{]'])
    
    for line_num, line in enumerate(lines, 1):
        for pattern in lang_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                block = extract_code_block(lines, line_num, language, include_comments)
                if block:
                    blocks.append(block)
                break  # Only match one pattern per line
    
    return blocks


@app.tool(
    description="Get code context around specific line numbers. "
                "Useful for understanding the surrounding code when analyzing specific vulnerabilities. "
                "Provides configurable context window size.",
    title="Get Code Context",
    annotations={
        "file_path": "Path to the file to get context from",
        "line_number": "Line number to get context around",
        "context_lines": "Number of lines before and after to include (default: 5)"
    }
)
async def get_code_context(
    file_path: str,
    line_number: int,
    context_lines: int = 5
) -> str:
    """
    Get code context around specific line numbers.
    
    This tool helps vulnerability validation agents understand the surrounding code
    when analyzing specific vulnerabilities, providing better context for validation.
    
    Args:
        file_path: Path to the file to get context from
        line_number: Line number to get context around
        context_lines: Number of lines before and after to include
    
    Returns:
        JSON string containing:
        - context: Code context with line numbers
        - target_line: The specific line being analyzed
        - metadata: Context metadata
        - success: Boolean indicating if operation was successful
        - error: Error message if operation failed
        
    Example:
        >>> get_code_context("src/auth.py", 42, 3)
        '{"success": true, "context": [...], "target_line": {...}}'
    """
    is_valid, error_msg, file_path_obj = validate_path_within_base(file_path)
    if not is_valid:
        return json.dumps({
            "success": False,
            "context": [],
            "target_line": {},
            "metadata": {},
            "error": error_msg
        }, indent=2)
    
    if not file_path_obj.is_file():
        return json.dumps({
            "success": False,
            "context": [],
            "target_line": {},
            "metadata": {},
            "error": f"Path is not a file: {file_path}"
        }, indent=2)
    
    try:
        with open(file_path_obj, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if line_number < 1 or line_number > len(lines):
            return json.dumps({
                "success": False,
                "context": [],
                "target_line": {},
                "metadata": {},
                "error": f"Line number {line_number} is out of range (1-{len(lines)})"
            }, indent=2)
        
        # Calculate context range
        start_line = max(1, line_number - context_lines)
        end_line = min(len(lines), line_number + context_lines)
        
        # Extract context
        context = []
        for i in range(start_line - 1, end_line):
            line_num = i + 1
            line_content = lines[i].rstrip('\n\r')
            
            context.append({
                "line_number": line_num,
                "content": line_content,
                "is_target": line_num == line_number
            })
        
        target_line = {
            "line_number": line_number,
            "content": lines[line_number - 1].rstrip('\n\r'),
            "context_before": context_lines,
            "context_after": context_lines
        }
        
        metadata = {
            "file_path": str(file_path_obj),
            "relative_path": get_relative_path(file_path_obj),
            "language": get_language_from_extension(file_path_obj),
            "total_lines": len(lines),
            "context_size": context_lines
        }
        
        result = {
            "success": True,
            "context": context,
            "target_line": target_line,
            "metadata": metadata,
            "error": None
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "context": [],
            "target_line": {},
            "metadata": {},
            "error": f"Error getting code context: {str(e)}"
        }, indent=2)


async def main():
    """
    Main function to run the vulnerability validation filesystem MCP server.
    
    This server provides AI agents with focused file system operations
    optimized for vulnerability validation and false positive detection.
    
    The server is restricted to operate only within the specified base directory
    for security purposes.
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
            print("Usage: python file_system_validate.py <base_directory>", file=sys.stderr)
            print("Example: python file_system_validate.py /path/to/project", file=sys.stderr)
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
        
        # Run the FastMCP server
        app.run()
            
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("Received KeyboardInterrupt, shutting down gracefully", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)