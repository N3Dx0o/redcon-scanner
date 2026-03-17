"""
Facts Tools - AI Agent Tools for Collecting and Managing Codebase Facts

This module provides tools for AI agents to collect, store, retrieve, and manage
facts about a codebase during security analysis. Facts represent discovered knowledge
about architecture, data flows, attack surfaces, dependencies, and other security-relevant
aspects of the codebase.

Fact Types (matching db.models.FactType):
- ARCHITECTURE: System architecture, components, and their relationships
- ATTACK_SURFACE: Entry points, exposed endpoints, and potential attack vectors
- DEPENDENCY: Third-party libraries, packages, and their versions/vulnerabilities
- DATA_FLOW: How data moves through the system, transformations, and storage
- ACCESS_CONTROL: Authentication and authorization mechanisms
- DANGEROUS_FUNCTION: Use of dangerous functions, unsafe patterns
- VALIDATION: Input validation and sanitization practices
- CRYPTO: Cryptographic implementations, algorithms, key management
- STATE_LOGIC: State management and business logic with security implications
- EXTERNAL_INTERACTION: External service integrations and communications
- THREAT_MODEL: Identified threats and threat modeling insights
"""

from db import get_orm, Project, Fact
from db.models import FactType
from typing import Annotated, List, Dict, Any, Optional


# ============================================================================
# FACT CREATION FUNCTIONS - One for each fact type
# ============================================================================

async def create_architecture_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the architectural fact discovered. Include component names, relationships, patterns, and security implications."]
) -> str:
    """
    Record an architectural fact about the codebase.
    
    Use this to document discovered architectural patterns, component relationships,
    service boundaries, layer structures, and design patterns that have security implications.
    
    EXAMPLES OF WHAT TO RECORD:
    - "The application follows a microservices architecture with 5 services communicating via REST APIs"
    - "The frontend is a React SPA that communicates with a Flask backend through /api/* endpoints"
    - "The system uses an event-driven architecture with RabbitMQ as the message broker"
    - "Database access is centralized through a repository pattern in src/repositories/"
    - "The application uses a monolithic architecture with no clear separation of concerns"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the architectural discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.ARCHITECTURE)


async def create_attack_surface_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the attack surface discovered. Include endpoint paths, methods, authentication requirements, and potential vulnerabilities."]
) -> str:
    """
    Record an attack surface fact about the codebase.
    
    Use this to document exposed endpoints, entry points, APIs, WebSocket connections,
    file upload handlers, and any other interface that could be targeted by attackers.
    
    EXAMPLES OF WHAT TO RECORD:
    - "POST /api/v2/upload accepts file uploads without size limits or type validation"
    - "WebSocket endpoint /ws/chat allows unauthenticated connections"
    - "GraphQL endpoint at /graphql exposes introspection in production"
    - "Admin panel at /admin/ is accessible without IP restrictions"
    - "The /api/users endpoint exposes user enumeration through different error messages"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the attack surface discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.ATTACK_SURFACE)


async def create_dependency_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the dependency discovered. Include package name, version, known vulnerabilities, and usage context."]
) -> str:
    """
    Record a dependency fact about the codebase.
    
    Use this to document third-party libraries, packages, frameworks, and their versions,
    especially those with known vulnerabilities or security concerns.
    
    EXAMPLES OF WHAT TO RECORD:
    - "The project uses lodash@4.17.15 which has prototype pollution vulnerability CVE-2020-8203"
    - "express@4.17.1 is used with body-parser that has known DoS vulnerabilities"
    - "The application depends on an unmaintained package 'abandoned-lib' last updated 3 years ago"
    - "OpenSSL 1.0.2k is used which is past end-of-life and has multiple CVEs"
    - "The project uses jwt-simple which has known algorithm confusion vulnerabilities"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the dependency discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.DEPENDENCY)


async def create_data_flow_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the data flow discovered. Include data sources, transformations, storage, and potential exposure points."]
) -> str:
    """
    Record a data flow fact about the codebase.
    
    Use this to document how sensitive data moves through the application, where it's
    stored, how it's transformed, and where it might be exposed or leaked.
    
    EXAMPLES OF WHAT TO RECORD:
    - "User passwords flow from login form -> /api/auth/login -> bcrypt hash -> users table"
    - "Credit card numbers are passed to payment gateway but also logged in debug mode"
    - "PII data from user registration is stored unencrypted in the MongoDB users collection"
    - "Session tokens are stored in localStorage instead of httpOnly cookies"
    - "API responses include internal database IDs that could enable IDOR attacks"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the data flow discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.DATA_FLOW)


async def create_access_control_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the access control mechanism discovered. Include auth type, permission model, and potential weaknesses."]
) -> str:
    """
    Record an access control fact about the codebase.
    
    Use this to document authentication and authorization mechanisms, including
    login flows, session management, permission systems, and related security concerns.
    
    EXAMPLES OF WHAT TO RECORD:
    - "Authentication uses JWT tokens with 24-hour expiration stored in localStorage"
    - "Authorization uses RBAC with roles: admin, user, guest defined in roles.py"
    - "No rate limiting on /api/login endpoint, allowing brute force attacks"
    - "Permission checks are missing on /api/admin/* endpoints after authentication"
    - "Session cookies lack Secure and HttpOnly flags"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the access control discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.ACCESS_CONTROL)


async def create_crypto_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the cryptographic implementation discovered. Include algorithms, key sizes, modes of operation, and potential weaknesses."]
) -> str:
    """
    Record a cryptography fact about the codebase.
    
    Use this to document cryptographic implementations, algorithm choices, key management
    practices, and any crypto-related security concerns.
    
    EXAMPLES OF WHAT TO RECORD:
    - "The application uses MD5 for password hashing instead of bcrypt or argon2"
    - "AES-128-ECB mode is used for encryption, which leaks patterns in ciphertext"
    - "RSA keys are generated with 1024 bits which is below recommended minimum of 2048"
    - "JWT tokens use HS256 with a hardcoded secret key found in config.py"
    - "TLS 1.0 and 1.1 are enabled on the server configuration"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the cryptographic discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.CRYPTO)


async def create_validation_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the input validation discovered. Include validation methods, sanitization practices, and potential injection points."]
) -> str:
    """
    Record an input validation fact about the codebase.
    
    Use this to document input validation practices, sanitization methods, encoding
    strategies, and areas where validation is missing or insufficient.
    
    EXAMPLES OF WHAT TO RECORD:
    - "User input in /api/search is passed directly to SQL query without sanitization"
    - "File upload endpoint validates extension but not MIME type or magic bytes"
    - "HTML output encoding is missing in user comment display, enabling XSS"
    - "JSON parsing uses eval() instead of JSON.parse() in legacy code"
    - "URL redirect parameter is not validated against whitelist, enabling open redirect"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the validation discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.VALIDATION)


async def create_dangerous_function_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the dangerous function usage discovered. Include function name, file location, and potential exploitation scenario."]
) -> str:
    """
    Record a dangerous function usage fact about the codebase.
    
    Use this to document usage of dangerous functions, unsafe patterns, deprecated
    methods, and code constructs that could lead to security vulnerabilities.
    
    EXAMPLES OF WHAT TO RECORD:
    - "eval() is used in utils/template.py:45 to process user-provided template strings"
    - "subprocess.shell=True used in deploy.py:123 with unsanitized user input"
    - "pickle.loads() deserializes untrusted data from network in api/data.py:89"
    - "dangerouslySetInnerHTML used with user content in components/Comment.jsx:34"
    - "strcpy() used without bounds checking in native/buffer.c:156"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the dangerous function discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.DANGEROUS_FUNCTION)


async def create_state_logic_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the state/business logic discovered. Include the logic, its implementation, and potential security implications."]
) -> str:
    """
    Record a state/business logic fact about the codebase.
    
    Use this to document business rules, application logic, workflow processes,
    state management, and business constraints that have security implications.
    
    EXAMPLES OF WHAT TO RECORD:
    - "Discount codes can be applied multiple times per order due to missing deduplication"
    - "Account lockout after 5 failed attempts but no cooldown period between attempts"
    - "Refund logic doesn't verify original payment method, enabling payment fraud"
    - "Inventory check happens before payment, allowing race condition exploitation"
    - "User deletion is soft-delete only but authentication still accepts deleted accounts"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the state/business logic discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.STATE_LOGIC)


async def create_external_interaction_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the external interaction discovered. Include service names, protocols, and security configurations."]
) -> str:
    """
    Record an external interaction fact about the codebase.
    
    Use this to document external service integrations, third-party APIs,
    database connections, and network communications.
    
    EXAMPLES OF WHAT TO RECORD:
    - "Application connects to PostgreSQL database at db.example.com without SSL"
    - "Stripe API integration uses hardcoded API key in payment_service.py"
    - "S3 bucket access uses public read permissions for user uploads"
    - "Redis connection at localhost:6379 has no authentication configured"
    - "Webhook endpoint /api/webhook accepts requests without signature verification"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the external interaction discovery
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.EXTERNAL_INTERACTION)


async def create_threat_model_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the threat model insight discovered. Include threat actors, attack vectors, assets at risk, and potential mitigations."]
) -> str:
    """
    Record a threat model fact about the codebase.
    
    Use this to document threat modeling insights, identified threat actors,
    attack scenarios, trust boundaries, and security assumptions.
    
    EXAMPLES OF WHAT TO RECORD:
    - "STRIDE analysis: Spoofing possible via JWT token theft from localStorage"
    - "Trust boundary identified between public API and internal microservices"
    - "High-value asset: user payment information stored in payments table"
    - "Threat actor: Malicious insider with database read access could exfiltrate PII"
    - "Attack tree: Account takeover via password reset flow manipulation"
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the threat model insight
        
    Returns:
        str: Success message with fact ID or error message
    """
    return await _create_fact(project_id, content, FactType.THREAT_MODEL)


# ============================================================================
# GENERIC FACT CREATION
# ============================================================================

async def create_fact(
    project_id: Annotated[int, "The unique identifier of the project this fact belongs to"],
    content: Annotated[str, "Detailed description of the fact discovered"],
    fact_type: Annotated[str, "Type of fact: architecture, attack_surface, dependency, data_flow, access_control, dangerous_function, validation, cryptography, state_logic, external_interaction, threat_model"]
) -> str:
    """
    Record a fact about the codebase with a specified type.
    
    This is a generic function to create any type of fact. For better documentation
    and type safety, prefer using the specific create_*_fact functions.
    
    Args:
        project_id: The project this fact belongs to
        content: Detailed description of the fact
        fact_type: Type of fact (must be one of the valid FactType values)
        
    Returns:
        str: Success message with fact ID or error message
    """
    try:
        fact_type_enum = FactType(fact_type.lower())
    except ValueError:
        valid_types = [t.value for t in FactType]
        return f"Error: Invalid fact type '{fact_type}'. Valid types: {valid_types}"
    
    return await _create_fact(project_id, content, fact_type_enum)


# ============================================================================
# INTERNAL HELPER FUNCTION
# ============================================================================

async def _create_fact(
    project_id: int,
    content: str,
    fact_type: FactType
) -> str:
    """Internal helper to create a fact record in the database."""
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Verify project exists
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return f"Error: Project with ID {project_id} not found"
            
            # Create the fact
            fact = Fact(
                content=content,
                type=fact_type,
                project_id=project_id
            )
            session.add(fact)
            session.commit()
            session.refresh(fact)
            
            msg = f"[SUCCESS] Created {fact_type.value} fact (ID: {fact.id}) for project '{project.name}'"
            print(msg)
            return msg
            
    except Exception as e:
        msg = f"Error creating fact: {str(e)}"
        print(f"[ERROR] {msg}")
        return msg


# ============================================================================
# FACT RETRIEVAL FUNCTIONS
# ============================================================================

async def get_project_facts(
    project_id: Annotated[int, "The unique identifier of the project to get facts for"],
    fact_type: Annotated[Optional[str], "Optional filter by fact type"] = None
) -> List[Dict[str, Any]]:
    """
    Get all facts for a project, optionally filtered by type.
    
    Args:
        project_id: The project ID
        fact_type: Optional fact type filter
        
    Returns:
        List of fact dictionaries
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            query = session.query(Fact).filter(Fact.project_id == project_id)
            
            if fact_type:
                try:
                    fact_type_enum = FactType(fact_type.lower())
                    query = query.filter(Fact.type == fact_type_enum)
                except ValueError:
                    valid_types = [t.value for t in FactType]
                    return [{"error": f"Invalid fact type '{fact_type}'. Valid types: {valid_types}"}]
            
            facts = query.order_by(Fact.created_at.desc()).all()
            
            return [
                {
                    "id": fact.id,
                    "type": fact.type.value,
                    "content": fact.content,
                    "created_at": fact.created_at.isoformat(),
                    "updated_at": fact.updated_at.isoformat()
                }
                for fact in facts
            ]
            
    except Exception as e:
        return [{"error": f"Error retrieving facts: {str(e)}"}]


async def get_fact_by_id(
    fact_id: Annotated[int, "The unique identifier of the fact to retrieve"]
) -> Dict[str, Any]:
    """
    Get a specific fact by its ID.
    
    Args:
        fact_id: The fact ID
        
    Returns:
        Dict containing fact details
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            fact = session.query(Fact).filter(Fact.id == fact_id).first()
            
            if not fact:
                return {"error": f"Fact with ID {fact_id} not found"}
            
            return {
                "id": fact.id,
                "type": fact.type.value,
                "content": fact.content,
                "project_id": fact.project_id,
                "created_at": fact.created_at.isoformat(),
                "updated_at": fact.updated_at.isoformat()
            }
            
    except Exception as e:
        return {"error": f"Error retrieving fact: {str(e)}"}


async def search_facts(
    project_id: Annotated[int, "The project ID to search within"],
    query: Annotated[str, "Search term to look for in fact content"]
) -> List[Dict[str, Any]]:
    """
    Search facts by content within a project.
    
    Args:
        project_id: The project ID
        query: Search term
        
    Returns:
        List of matching facts
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            facts = session.query(Fact).filter(
                Fact.project_id == project_id,
                Fact.content.ilike(f"%{query}%")
            ).order_by(Fact.created_at.desc()).all()
            
            return [
                {
                    "id": fact.id,
                    "type": fact.type.value,
                    "content": fact.content,
                    "created_at": fact.created_at.isoformat()
                }
                for fact in facts
            ]
            
    except Exception as e:
        return [{"error": f"Error searching facts: {str(e)}"}]


async def get_facts_summary(
    project_id: Annotated[int, "The project ID to get summary for"]
) -> Dict[str, Any]:
    """
    Get a summary of facts by type for a project.
    
    Args:
        project_id: The project ID
        
    Returns:
        Dict containing fact counts by type and recent facts
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Verify project exists
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return {"error": f"Project with ID {project_id} not found"}
            
            # Count facts by type
            from sqlalchemy import func
            counts = session.query(
                Fact.type,
                func.count(Fact.id).label('count')
            ).filter(
                Fact.project_id == project_id
            ).group_by(Fact.type).all()
            
            counts_by_type = {t.value: 0 for t in FactType}
            for fact_type, count in counts:
                counts_by_type[fact_type.value] = count
            
            total_facts = sum(counts_by_type.values())
            
            # Get most recent facts
            recent_facts = session.query(Fact).filter(
                Fact.project_id == project_id
            ).order_by(Fact.created_at.desc()).limit(5).all()
            
            return {
                "project_id": project_id,
                "project_name": project.name,
                "total_facts": total_facts,
                "facts_by_type": counts_by_type,
                "recent_facts": [
                    {
                        "id": fact.id,
                        "type": fact.type.value,
                        "content": fact.content[:200] + "..." if len(fact.content) > 200 else fact.content,
                        "created_at": fact.created_at.isoformat()
                    }
                    for fact in recent_facts
                ]
            }
            
    except Exception as e:
        return {"error": f"Error getting facts summary: {str(e)}"}


# ============================================================================
# FACT MANAGEMENT FUNCTIONS
# ============================================================================

async def update_fact(
    fact_id: Annotated[int, "The unique identifier of the fact to update"],
    content: Annotated[str, "New content for the fact"]
) -> str:
    """
    Update the content of an existing fact.
    
    Args:
        fact_id: The fact ID
        content: New content
        
    Returns:
        str: Success or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            fact = session.query(Fact).filter(Fact.id == fact_id).first()
            
            if not fact:
                return f"Error: Fact with ID {fact_id} not found"
            
            fact.content = content
            session.commit()
            
            return f"[SUCCESS] Updated fact ID {fact_id}"
            
    except Exception as e:
        return f"Error updating fact: {str(e)}"


async def delete_fact(
    fact_id: Annotated[int, "The unique identifier of the fact to delete"]
) -> str:
    """
    Delete a fact from the database.
    
    Args:
        fact_id: The fact ID
        
    Returns:
        str: Success or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            fact = session.query(Fact).filter(Fact.id == fact_id).first()
            
            if not fact:
                return f"Error: Fact with ID {fact_id} not found"
            
            session.delete(fact)
            session.commit()
            
            return f"[SUCCESS] Deleted fact ID {fact_id}"
            
    except Exception as e:
        return f"Error deleting fact: {str(e)}"


async def delete_project_facts(
    project_id: Annotated[int, "The project ID to delete facts for"],
    fact_type: Annotated[Optional[str], "Optional: only delete facts of this type"] = None
) -> str:
    """
    Delete all facts for a project, optionally filtered by type.
    
    Args:
        project_id: The project ID
        fact_type: Optional fact type filter
        
    Returns:
        str: Success message with count of deleted facts
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            query = session.query(Fact).filter(Fact.project_id == project_id)
            
            if fact_type:
                try:
                    fact_type_enum = FactType(fact_type.lower())
                    query = query.filter(Fact.type == fact_type_enum)
                except ValueError:
                    valid_types = [t.value for t in FactType]
                    return f"Error: Invalid fact type '{fact_type}'. Valid types: {valid_types}"
            
            count = query.count()
            query.delete(synchronize_session='fetch')
            session.commit()
            
            type_msg = f" of type '{fact_type}'" if fact_type else ""
            return f"[SUCCESS] Deleted {count} facts{type_msg} for project {project_id}"
            
    except Exception as e:
        return f"Error deleting facts: {str(e)}"


# ============================================================================
# BULK OPERATIONS
# ============================================================================

async def bulk_create_facts(
    project_id: Annotated[int, "The project ID"],
    facts: Annotated[List[Dict[str, str]], "List of facts with 'type' and 'content' keys"]
) -> str:
    """
    Create multiple facts at once for a project.
    
    Args:
        project_id: The project ID
        facts: List of dicts with 'type' and 'content' keys
        
    Returns:
        str: Success message with count of created facts
        
    Example:
        await bulk_create_facts(1, [
            {"type": "architecture", "content": "Uses microservices pattern"},
            {"type": "access_control", "content": "JWT-based authentication"},
            {"type": "cryptography", "content": "AES-256 for data encryption"}
        ])
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Verify project exists
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return f"Error: Project with ID {project_id} not found"
            
            created_count = 0
            errors = []
            
            for fact_data in facts:
                try:
                    fact_type = FactType(fact_data.get('type', '').lower())
                    content = fact_data.get('content', '')
                    
                    if not content:
                        errors.append(f"Empty content for type {fact_type.value}")
                        continue
                    
                    fact = Fact(
                        content=content,
                        type=fact_type,
                        project_id=project_id
                    )
                    session.add(fact)
                    created_count += 1
                    
                except ValueError as e:
                    errors.append(f"Invalid type: {fact_data.get('type')}")
            
            session.commit()
            
            result = f"[SUCCESS] Created {created_count} facts for project '{project.name}'"
            if errors:
                result += f". Errors: {'; '.join(errors)}"
            
            return result
            
    except Exception as e:
        return f"Error creating facts: {str(e)}"
