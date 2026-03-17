#!/usr/bin/env python3
"""
MCP Findings Server (SSE-based, API-driven)

A focused MCP server for managing findings within a specific project using SSE.
This server provides read-only operations by fetching data from the Flask API.

IMPORTANT FEATURES:
- All operations are restricted to a specific project specified at startup
- The server will only access findings from the designated project
- Read-only operations via API calls to localhost:5555
- Uses SSE (Server-Sent Events) transport for MCP communication

Key Features:
- List findings with filtering options
- List findings by severity level
- List findings with open status
- Find findings by file path
- Get finding details by ID
- Search findings by title/description

Command Line Usage:
    python findings_server.py <base_url> <project_id>
    OR
    BASE_URL=<base_url> PROJECT_ID=<project_id> python findings_server.py
    
Example:
    python findings_server.py http://localhost:5555 1
    BASE_URL=http://localhost:5555 PROJECT_ID=1 python findings_server.py
"""

import asyncio
import json
import sys
import os
from typing import Any, Dict, List, Optional
import httpx

from mcp.server import FastMCP

# Global project ID and base URL - set at startup
PROJECT_ID: Optional[int] = None
BASE_URL: str = ""

# Create FastMCP server instance
app = FastMCP("findings-server")


def set_project(base_url: str, project_id: int) -> None:
    """
    Set the base URL and project ID and verify project exists via API.
    
    Args:
        base_url: Base URL of the Flask API (e.g., http://localhost:5555)
        project_id: ID of the project to filter findings by
        
    Raises:
        ValueError: If the project doesn't exist
        SystemExit: If initialization fails
    """
    global PROJECT_ID, BASE_URL
    
    try:
        BASE_URL = base_url.rstrip('/')
        PROJECT_ID = project_id
        
        # Verify project exists via API
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{BASE_URL}/api/projects/{project_id}")
            
            if response.status_code == 404:
                raise ValueError(f"Project with ID {project_id} not found")
            
            if response.status_code != 200:
                raise ValueError(f"Error checking project: {response.text}")
            
            data = response.json()
            if not data.get('success'):
                raise ValueError(f"Error checking project: {data.get('error', 'Unknown error')}")
            
            project = data.get('project', {})
            print(f"Project set to: {project.get('name')} (ID: {PROJECT_ID})", file=sys.stderr)
            
    except httpx.RequestError as e:
        print(f"Error connecting to API at {BASE_URL}: {str(e)}", file=sys.stderr)
        print(f"Make sure the Flask server is running on port 5555", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error setting project {project_id}: {str(e)}", file=sys.stderr)
        sys.exit(1)


@app.tool(
    description="List findings for the project with optional filtering. "
               "Supports filtering by severity, status, and search terms.",
    title="List Findings",
    annotations={
        "severity": "Filter by severity (critical, high, medium, low, info) - optional",
        "status": "Filter by status (open, in_progress, resolved, false_positive, ignored) - optional",
        "search": "Search term to filter by title or description - optional",
        "limit": "Maximum number of findings to return (default: 100)",
        "offset": "Number of findings to skip for pagination (default: 0)"
    }
)
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> str:
    """
    List findings for the project with optional filtering.
    
    Args:
        severity: Filter by severity level (optional)
        status: Filter by status (optional)
        search: Search term for title/description (optional)
        limit: Maximum number of findings to return
        offset: Number of findings to skip for pagination
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - findings: Array of finding dictionaries
        - total: Total number of findings matching the filters
        - error: Error message if operation failed
    """
    global PROJECT_ID
    
    if PROJECT_ID is None:
        return json.dumps({
            "success": False,
            "findings": [],
            "total": 0,
            "error": "Project not set"
        }, indent=2)
    
    try:
        # Build query parameters
        params = {
            "project_id": PROJECT_ID,
            "limit": limit,
            "offset": offset
        }
        
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        
        # Make API request
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{BASE_URL}/api/findings", params=params)
            
            if response.status_code != 200:
                return json.dumps({
                    "success": False,
                    "findings": [],
                    "total": 0,
                    "error": f"API error: {response.status_code} - {response.text}"
                }, indent=2)
            
            data = response.json()
            
            if not data.get('success'):
                return json.dumps({
                    "success": False,
                    "findings": [],
                    "total": 0,
                    "error": data.get('error', 'Unknown error')
                }, indent=2)
            
            result = {
                "success": True,
                "findings": data.get('findings', []),
                "total": data.get('total', 0),
                "limit": limit,
                "offset": offset,
                "project_id": PROJECT_ID,
                "error": None
            }
            
            return json.dumps(result, indent=2)
            
    except httpx.RequestError as e:
        return json.dumps({
            "success": False,
            "findings": [],
            "total": 0,
            "error": f"Connection error: {str(e)}"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "findings": [],
            "total": 0,
            "error": f"Error listing findings: {str(e)}"
        }, indent=2)


@app.tool(
    description="Get detailed information about a specific finding by its ID.",
    title="Get Finding",
    annotations={
        "finding_id": "The ID of the finding to retrieve"
    }
)
async def get_finding(finding_id: int) -> str:
    """
    Get detailed information about a specific finding by its ID.
    
    Args:
        finding_id: The ID of the finding to retrieve
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - finding: Finding dictionary or None if not found
        - error: Error message if operation failed
    """
    global PROJECT_ID
    
    if PROJECT_ID is None:
        return json.dumps({
            "success": False,
            "finding": None,
            "error": "Project not set"
        }, indent=2)
    
    try:
        # Make API request to get the finding
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{BASE_URL}/api/findings/{finding_id}")
            
            if response.status_code == 404:
                return json.dumps({
                    "success": False,
                    "finding": None,
                    "error": f"Finding with ID {finding_id} not found"
                }, indent=2)
            
            if response.status_code != 200:
                return json.dumps({
                    "success": False,
                    "finding": None,
                    "error": f"API error: {response.status_code} - {response.text}"
                }, indent=2)
            
            data = response.json()
            
            if not data.get('success'):
                return json.dumps({
                    "success": False,
                    "finding": None,
                    "error": data.get('error', 'Unknown error')
                }, indent=2)
            
            finding = data.get('finding')
            
            # Verify finding belongs to the project
            if finding and finding.get('project_id') != PROJECT_ID:
                return json.dumps({
                    "success": False,
                    "finding": None,
                    "error": f"Finding {finding_id} does not belong to project {PROJECT_ID}"
                }, indent=2)
            
            result = {
                "success": True,
                "finding": finding,
                "error": None
            }
            
            return json.dumps(result, indent=2)
            
    except httpx.RequestError as e:
        return json.dumps({
            "success": False,
            "finding": None,
            "error": f"Connection error: {str(e)}"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "finding": None,
            "error": f"Error getting finding: {str(e)}"
        }, indent=2)


@app.tool(
    description="Search findings by title or description text.",
    title="Search Findings",
    annotations={
        "query": "Search term to look for in finding titles and descriptions",
        "severity": "Optional severity filter (critical, high, medium, low, info)",
        "status": "Optional status filter (open, in_progress, resolved, false_positive, ignored)",
        "limit": "Maximum number of results to return (default: 50)"
    }
)
async def search_findings(
    query: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50
) -> str:
    """
    Search findings by title or description text.
    
    Args:
        query: Search term to look for in finding titles and descriptions
        severity: Optional severity filter
        status: Optional status filter
        limit: Maximum number of results to return
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - findings: Array of finding dictionaries
        - total: Total number of matching findings
        - error: Error message if operation failed
    """
    # Use list_findings with search parameter
    return await list_findings(
        severity=severity,
        status=status,
        search=query,
        limit=limit,
        offset=0
    )


@app.tool(
    description="List findings filtered by severity level.",
    title="List Findings by Severity",
    annotations={
        "severity": "Severity level to filter by (critical, high, medium, low, info)",
        "limit": "Maximum number of findings to return (default: 100)",
        "offset": "Number of findings to skip for pagination (default: 0)"
    }
)
async def list_findings_by_severity(
    severity: str,
    limit: int = 100,
    offset: int = 0
) -> str:
    """
    List findings filtered by severity level.
    
    Args:
        severity: Severity level to filter by (critical, high, medium, low, info)
        limit: Maximum number of findings to return
        offset: Number of findings to skip for pagination
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - findings: Array of finding dictionaries
        - total: Total number of findings matching the severity
        - error: Error message if operation failed
    """
    return await list_findings(
        severity=severity,
        limit=limit,
        offset=offset
    )


@app.tool(
    description="List findings with open status.",
    title="List Open Findings",
    annotations={
        "limit": "Maximum number of findings to return (default: 100)",
        "offset": "Number of findings to skip for pagination (default: 0)"
    }
)
async def list_open_findings(
    limit: int = 100,
    offset: int = 0
) -> str:
    """
    List findings with open status.
    
    Args:
        limit: Maximum number of findings to return
        offset: Number of findings to skip for pagination
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - findings: Array of finding dictionaries
        - total: Total number of open findings
        - error: Error message if operation failed
    """
    return await list_findings(
        status="open",
        limit=limit,
        offset=offset
    )


@app.tool(
    description="Find findings based on file path. Supports partial matching for flexible searching.",
    title="Find Findings by File Path",
    annotations={
        "file_path": "File path to search for (supports partial matching)",
        "limit": "Maximum number of findings to return (default: 100)",
        "offset": "Number of findings to skip for pagination (default: 0)"
    }
)
async def find_findings_by_file_path(
    file_path: str,
    limit: int = 100,
    offset: int = 0
) -> str:
    """
    Find findings based on file path. Supports partial matching for flexible searching.
    
    Args:
        file_path: File path to search for (supports partial matching)
        limit: Maximum number of findings to return
        offset: Number of findings to skip for pagination
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - findings: Array of finding dictionaries
        - total: Total number of findings matching the file path
        - error: Error message if operation failed
    """
    global PROJECT_ID
    
    if PROJECT_ID is None:
        return json.dumps({
            "success": False,
            "findings": [],
            "total": 0,
            "error": "Project not set"
        }, indent=2)
    
    try:
        # Build query parameters
        params = {
            "project_id": PROJECT_ID,
            "file_path": file_path,
            "limit": limit,
            "offset": offset
        }
        
        # Make API request
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{BASE_URL}/api/findings", params=params)
            
            if response.status_code != 200:
                return json.dumps({
                    "success": False,
                    "findings": [],
                    "total": 0,
                    "error": f"API error: {response.status_code} - {response.text}"
                }, indent=2)
            
            data = response.json()
            
            if not data.get('success'):
                return json.dumps({
                    "success": False,
                    "findings": [],
                    "total": 0,
                    "error": data.get('error', 'Unknown error')
                }, indent=2)
            
            result = {
                "success": True,
                "findings": data.get('findings', []),
                "total": data.get('total', 0),
                "file_path": file_path,
                "limit": limit,
                "offset": offset,
                "project_id": PROJECT_ID,
                "error": None
            }
            
            return json.dumps(result, indent=2)
            
    except httpx.RequestError as e:
        return json.dumps({
            "success": False,
            "findings": [],
            "total": 0,
            "error": f"Connection error: {str(e)}"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "findings": [],
            "total": 0,
            "error": f"Error finding findings by file path: {str(e)}"
        }, indent=2)


@app.tool(
    description="Get information about the project.",
    title="Get Project Info",
    annotations={}
)
async def get_project_info() -> str:
    """
    Get information about the project.
    
    Returns:
        JSON string containing:
        - success: Boolean indicating if operation was successful
        - project_info: Dictionary with project information
        - error: Error message if operation failed
    """
    global PROJECT_ID
    
    if PROJECT_ID is None:
        return json.dumps({
            "success": False,
            "project_info": {},
            "error": "Project not set"
        }, indent=2)
    
    try:
        # Make API request to get project info
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{BASE_URL}/api/projects/{PROJECT_ID}")
            
            if response.status_code == 404:
                return json.dumps({
                    "success": False,
                    "project_info": {},
                    "error": "Project not found"
                }, indent=2)
            
            if response.status_code != 200:
                return json.dumps({
                    "success": False,
                    "project_info": {},
                    "error": f"API error: {response.status_code} - {response.text}"
                }, indent=2)
            
            data = response.json()
            
            if not data.get('success'):
                return json.dumps({
                    "success": False,
                    "project_info": {},
                    "error": data.get('error', 'Unknown error')
                }, indent=2)
            
            result = {
                "success": True,
                "project_info": data.get('project', {}),
                "error": None
            }
            
            return json.dumps(result, indent=2)
            
    except httpx.RequestError as e:
        return json.dumps({
            "success": False,
            "project_info": {},
            "error": f"Connection error: {str(e)}"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "project_info": {},
            "error": f"Error getting project info: {str(e)}"
        }, indent=2)


async def main():
    """
    Main function to run the findings MCP server.
    
    This server provides read-only operations via API calls to localhost:5555.
    All operations are restricted to the project specified at startup.
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
        # Try to read from environment variables first
        base_url = os.getenv('BASE_URL')
        project_id_env = os.getenv('PROJECT_ID')
        
        # If env vars not set, try command line arguments
        if base_url is None or project_id_env is None:
            if len(sys.argv) != 3:
                print("Usage: python findings_server.py <base_url> <project_id>", file=sys.stderr)
                print("Or set environment variables: BASE_URL and PROJECT_ID", file=sys.stderr)
                print("Example: python findings_server.py http://localhost:5555 1", file=sys.stderr)
                print("Example: BASE_URL=http://localhost:5555 PROJECT_ID=1 python findings_server.py", file=sys.stderr)
                sys.exit(1)
            
            base_url = sys.argv[1]
            project_id_str = sys.argv[2]
        else:
            project_id_str = project_id_env
        
        # Parse project_id
        try:
            project_id = int(project_id_str)
        except ValueError:
            print(f"Error: project_id must be an integer, got: {project_id_str}", file=sys.stderr)
            sys.exit(1)
        
        # Set the project (this will exit if invalid)
        set_project(base_url, project_id)
        print(f"MCP Findings Server initialized for project ID: {PROJECT_ID}", file=sys.stderr)
        print(f"Connecting to API at: {BASE_URL}", file=sys.stderr)
        print(f"Server starting with SSE transport on http://127.0.0.1:8000/sse", file=sys.stderr)
        
        # Run the FastMCP server with SSE transport
        app.run(transport="sse")
            
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nReceived KeyboardInterrupt, shutting down gracefully", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
