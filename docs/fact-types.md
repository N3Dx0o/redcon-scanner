# Fact Types Documentation

This document describes the different types of facts that AI agents can collect during security analysis of a codebase. Facts represent discovered knowledge about the application's architecture, security posture, and potential vulnerabilities.

## Overview

Facts are categorized into 11 types, each capturing a specific aspect of the codebase relevant to security analysis:

| Type | Description |
|------|-------------|
| [Architecture](#architecture) | System structure, components, and design patterns |
| [Attack Surface](#attack-surface) | Entry points and potential attack vectors |
| [Dependency](#dependency) | Third-party libraries and their vulnerabilities |
| [Data Flow](#data-flow) | How data moves through the system |
| [Access Control](#access-control) | Authentication and authorization mechanisms |
| [Dangerous Function](#dangerous-function) | Unsafe function usage patterns |
| [Validation](#validation) | Input validation and sanitization |
| [Cryptography](#cryptography) | Cryptographic implementations |
| [State Logic](#state-logic) | State management and business rules |
| [External Interaction](#external-interaction) | External APIs and service integrations |
| [Threat Model](#threat-model) | Threat modeling insights |

---

## Architecture

**Type Value:** `architecture`

**Description:**  
Documents the overall system architecture, component relationships, service boundaries, layer structures, and design patterns. Understanding the architecture helps identify trust boundaries and potential security weak points in the system design.

**What to Look For:**
- Microservices vs monolithic design
- Frontend/backend separation
- API gateway patterns
- Message queues and event-driven patterns
- Database architecture
- Caching layers
- Load balancing and redundancy

**Examples:**

```
The application follows a microservices architecture with 5 services 
communicating via REST APIs over an internal network without mTLS.
```

```
The frontend is a React SPA that communicates with a Flask backend 
through /api/* endpoints. CORS is configured to allow all origins.
```

```
Database access is centralized through a repository pattern in 
src/repositories/. All queries pass through this layer.
```

```
The system uses an event-driven architecture with RabbitMQ as the 
message broker. Messages are not encrypted in transit.
```

```
Monolithic architecture with no clear separation of concerns. 
Business logic is mixed with data access code throughout controllers.
```

---

## Attack Surface

**Type Value:** `attack_surface`

**Description:**  
Documents exposed endpoints, entry points, APIs, WebSocket connections, file upload handlers, and any interface that could be targeted by attackers. This helps prioritize security testing efforts.

**What to Look For:**
- Public API endpoints
- File upload functionality
- WebSocket connections
- GraphQL introspection
- Admin interfaces
- Debug endpoints
- User enumeration vectors

**Examples:**

```
POST /api/v2/upload accepts file uploads without size limits or 
type validation. Files are stored in a publicly accessible S3 bucket.
```

```
WebSocket endpoint /ws/chat allows unauthenticated connections and 
broadcasts messages to all connected clients without filtering.
```

```
GraphQL endpoint at /graphql exposes introspection in production, 
revealing the entire API schema including internal types.
```

```
Admin panel at /admin/ is accessible without IP restrictions. 
Only protected by basic authentication over HTTP.
```

```
The /api/users endpoint exposes user enumeration through different 
error messages: "User not found" vs "Invalid password".
```

```
Debug endpoint /api/debug/logs is accessible in production and 
returns application logs including stack traces.
```

---

## Dependency

**Type Value:** `dependency`

**Description:**  
Documents third-party libraries, packages, frameworks, and their versions. Particularly important for identifying known vulnerabilities (CVEs) and outdated or unmaintained dependencies.

**What to Look For:**
- Packages with known CVEs
- Outdated major versions
- Unmaintained/abandoned packages
- Dependencies with security advisories
- Transitive dependency vulnerabilities
- License compliance issues

**Examples:**

```
The project uses lodash@4.17.15 which has prototype pollution 
vulnerability CVE-2020-8203. Used in user input processing.
```

```
express@4.17.1 is used with body-parser that has known DoS 
vulnerabilities via large JSON payloads.
```

```
The application depends on 'abandoned-lib' package, last updated 
3 years ago with 15 open security issues on GitHub.
```

```
OpenSSL 1.0.2k is used which is past end-of-life and has 
multiple CVEs including CVE-2020-1971.
```

```
The project uses jwt-simple which has known algorithm confusion 
vulnerabilities allowing signature bypass.
```

```
Python 2.7 runtime detected. Python 2 reached end-of-life in 
January 2020 and no longer receives security updates.
```

---

## Data Flow

**Type Value:** `data_flow`

**Description:**  
Documents how sensitive data moves through the application, where it's stored, how it's transformed, and where it might be exposed or leaked. Critical for understanding data exposure risks.

**What to Look For:**
- Sensitive data paths (PII, credentials, financial)
- Data storage locations and encryption
- Data transformation and sanitization
- Logging of sensitive data
- Data exposure in responses
- Cache storage of sensitive data

**Examples:**

```
User passwords flow from login form -> /api/auth/login -> bcrypt 
hash -> users table. Password is logged in debug mode before hashing.
```

```
Credit card numbers are passed to payment gateway but also stored 
in session storage and logged in application logs.
```

```
PII data from user registration is stored unencrypted in the 
MongoDB users collection. No field-level encryption applied.
```

```
Session tokens are stored in localStorage instead of httpOnly 
cookies, making them accessible to XSS attacks.
```

```
API responses include internal database IDs (sequential integers) 
that could enable IDOR attacks and user enumeration.
```

```
User search queries are logged with full request body including 
sensitive filters, stored for 90 days in CloudWatch.
```

---

## Access Control

**Type Value:** `access_control`

**Description:**  
Documents authentication mechanisms, authorization models, permission systems, role-based access control, session management, and related security concerns. Combines both authentication (who you are) and authorization (what you can do).

**What to Look For:**
- Authentication mechanisms (JWT, sessions, OAuth)
- Session management and token handling
- Role-based or attribute-based access control
- Permission checks on endpoints
- Privilege escalation vectors
- IDOR vulnerabilities

**Examples:**

```
Authentication uses JWT tokens with 24-hour expiration stored in 
localStorage. No refresh token rotation implemented.
```

```
Authorization uses RBAC with roles: admin, user, guest defined 
in roles.py. Role checks are inconsistent across endpoints.
```

```
Permission checks are missing on /api/admin/* endpoints after 
authentication. Any authenticated user can access admin functions.
```

```
IDOR vulnerability: user can access other users' data by changing 
user_id parameter in /api/users/{user_id}/profile endpoint.
```

```
Session cookies lack Secure and HttpOnly flags. SameSite attribute 
not set, vulnerable to CSRF attacks.
```

```
OAuth2 implementation doesn't validate state parameter in callback, 
vulnerable to CSRF-based account takeover.
```

```
No rate limiting on /api/login endpoint. Brute force attacks can 
attempt unlimited password guesses.
```

```
Password reset tokens are sequential integers that can be enumerated 
to take over arbitrary accounts.
```

---

## Dangerous Function

**Type Value:** `dangerous_function`

**Description:**  
Documents usage of dangerous functions, unsafe patterns, deprecated methods, and code constructs that could lead to security vulnerabilities. These require careful review and potential remediation.

**What to Look For:**
- Code execution functions (eval, exec)
- Command injection vectors (shell=True)
- Deserialization of untrusted data
- Unsafe HTML rendering
- Buffer operations without bounds checking
- Deprecated cryptographic functions

**Examples:**

```
eval() is used in utils/template.py:45 to process user-provided 
template strings. Allows arbitrary code execution.
```

```
subprocess.call() with shell=True used in deploy.py:123 with 
unsanitized user input from form field.
```

```
pickle.loads() deserializes untrusted data from network request 
in api/data.py:89. Enables remote code execution.
```

```
dangerouslySetInnerHTML used with user-generated content in 
components/Comment.jsx:34 without sanitization.
```

```
strcpy() used without bounds checking in native/buffer.c:156. 
Buffer overflow possible with long input strings.
```

```
yaml.load() used instead of yaml.safe_load() in config/loader.py:23. 
Allows arbitrary Python object instantiation.
```

```
SQL query built with string formatting in models/user.py:67:
f"SELECT * FROM users WHERE id = {user_id}"
```

---

## Validation

**Type Value:** `validation`

**Description:**  
Documents input validation practices, sanitization methods, encoding strategies, and areas where validation is missing or insufficient. Critical for preventing injection attacks.

**What to Look For:**
- Missing input validation
- Incomplete sanitization
- Output encoding gaps
- Type coercion issues
- Length/size limits
- Allowlist vs blocklist validation

**Examples:**

```
User input in /api/search is passed directly to SQL query without 
parameterization or sanitization. SQL injection possible.
```

```
File upload endpoint validates extension (.jpg, .png) but not MIME 
type or magic bytes. Allows uploading PHP files as .jpg.
```

```
HTML output encoding is missing in user comment display template 
(templates/comments.html:45). XSS via stored comments possible.
```

```
JSON parsing uses eval() instead of JSON.parse() in legacy code 
at static/js/utils.js:123 for backward compatibility.
```

```
URL redirect parameter 'next' is not validated against whitelist. 
Open redirect possible: /login?next=https://evil.com
```

```
Email validation uses regex that doesn't handle all edge cases. 
Allows malformed emails that could bypass filters.
```

```
Integer overflow possible: user-provided quantity value not checked 
for maximum bounds before multiplication in cart calculation.
```

---

## Cryptography

**Type Value:** `cryptography`

**Description:**  
Documents cryptographic implementations, algorithm choices, key management practices, secrets handling, and crypto-related security concerns. Weak cryptography can undermine all other security measures.

**What to Look For:**
- Weak hashing algorithms (MD5, SHA1 for passwords)
- Insecure encryption modes (ECB)
- Insufficient key lengths
- Hardcoded secrets and keys
- Poor random number generation
- Certificate validation issues
- Secrets in source code

**Examples:**

```
The application uses MD5 for password hashing in auth/password.py:34 
instead of bcrypt, argon2, or scrypt.
```

```
AES-128-ECB mode is used for encryption in crypto/encrypt.py:56. 
ECB mode leaks patterns in ciphertext.
```

```
RSA keys are generated with 1024 bits in security/keys.py:23. 
Below recommended minimum of 2048 bits.
```

```
JWT tokens use HS256 with a hardcoded secret key found in 
config.py:12: SECRET_KEY = "super-secret-key-123"
```

```
TLS 1.0 and 1.1 are enabled in nginx.conf. These protocols have 
known vulnerabilities and should be disabled.
```

```
AWS credentials hardcoded in config/settings.py:45, committed 
to git history. Keys still active and valid.
```

```
Private keys stored in source code at certs/private.pem with 
world-readable permissions (644).
```

```
Math.random() used for generating password reset tokens in 
auth/reset.js:78. Not cryptographically secure.
```

---

## State Logic

**Type Value:** `state_logic`

**Description:**  
Documents state management patterns, business rules, workflow processes, state machines, and business constraints that have security implications. Logic flaws can lead to fraud and abuse.

**What to Look For:**
- Race conditions in state transitions
- Missing state validation
- Business rule bypasses
- Inconsistent state handling
- Time-of-check to time-of-use (TOCTOU) bugs
- Replay attack vectors

**Examples:**

```
Discount codes can be applied multiple times per order due to 
missing deduplication check in cart/discounts.py:89.
```

```
Account lockout after 5 failed attempts but no cooldown period. 
Attacker can wait 1 second and retry indefinitely.
```

```
Refund logic doesn't verify original payment method in 
payments/refund.py:45. Enables payment method switching fraud.
```

```
Inventory check happens before payment processing. Race condition 
allows overselling of limited stock items.
```

```
User deletion is soft-delete only but authentication in 
auth/login.py still accepts deleted account credentials.
```

```
State machine allows transition from 'cancelled' back to 'active' 
order status via direct API call, bypassing cancellation fees.
```

```
Shopping cart prices stored client-side in JavaScript. Price 
manipulation possible by modifying localStorage before checkout.
```

```
Coupon validation happens client-side. Server accepts any 
discount percentage sent in the checkout request.
```

---

## External Interaction

**Type Value:** `external_interaction`

**Description:**  
Documents external API calls, third-party service integrations, webhook handlers, external database connections, and cloud service interactions. External boundaries are common attack vectors.

**What to Look For:**
- SSRF vulnerabilities
- Webhook signature validation
- API key exposure
- Unencrypted external connections
- Trust of external headers
- Callback validation

**Examples:**

```
Application calls Stripe API with API key passed in query string 
instead of Authorization header. Key visible in logs.
```

```
Webhook endpoint /api/webhooks/payment accepts requests without 
signature verification. Allows forged payment confirmations.
```

```
External API responses are cached without validation in Redis. 
Cache poisoning possible via compromised API response.
```

```
SSRF possible via user-controlled URL parameter in 
/api/fetch-preview endpoint. Can access internal services.
```

```
Redis connection uses unencrypted connection to external Redis 
cluster at redis.example.com:6379.
```

```
Application trusts X-Forwarded-For header from any source for 
IP-based rate limiting. Easily bypassed with spoofed header.
```

```
External OAuth callback doesn't validate that the authorization 
code came from a request we initiated.
```

```
S3 bucket policy allows public read access. External API stores 
sensitive reports that are publicly accessible.
```

---

## Threat Model

**Type Value:** `threat_model`

**Description:**  
Documents threat modeling insights, identified threat actors, attack scenarios, trust boundaries, security assumptions, and high-level security observations. Provides strategic security context.

**What to Look For:**
- Trust boundaries
- High-value assets
- Threat actors and motivations
- Attack trees and scenarios
- Security assumptions
- STRIDE analysis findings

**Examples:**

```
STRIDE Analysis - Spoofing: JWT token theft from localStorage 
enables complete account takeover. No additional verification.
```

```
Trust boundary identified between public API gateway and internal 
microservices. No authentication between internal services.
```

```
High-value asset identified: user payment information stored in 
payments.card_details table. PCI DSS scope applies.
```

```
Threat actor profile: Malicious insider with database read access 
could exfiltrate all user PII. No data access logging.
```

```
Attack tree: Account takeover possible via:
1. Password reset link interception (email compromise)
2. Session token theft via XSS
3. OAuth state parameter CSRF
```

```
Security assumption: All internal services are trusted. No 
service-to-service authentication or authorization implemented.
```

```
Repudiation risk: No audit logging for administrative actions. 
Malicious admin actions cannot be traced.
```

```
Denial of Service vector: /api/export endpoint generates large 
reports synchronously. No rate limiting or async processing.
```

---

## Usage in Code

### Creating Facts with Specific Functions

```python
from ai_tools.facts_tools import (
    create_architecture_fact,
    create_attack_surface_fact,
    create_dependency_fact,
    create_data_flow_fact,
    create_access_control_fact,
    create_dangerous_function_fact,
    create_validation_fact,
    create_crypto_fact,
    create_state_logic_fact,
    create_external_interaction_fact,
    create_threat_model_fact,
)

# Record an architecture finding
await create_architecture_fact(
    project_id=1,
    content="Microservices architecture with 5 services using REST APIs"
)

# Record a vulnerability in dependencies
await create_dependency_fact(
    project_id=1,
    content="lodash@4.17.15 has prototype pollution CVE-2020-8203"
)
```

### Creating Facts with Generic Function

```python
from ai_tools.facts_tools import create_fact

await create_fact(
    project_id=1,
    content="JWT tokens stored in localStorage",
    fact_type="access_control"
)
```

### Bulk Creating Facts

```python
from ai_tools.facts_tools import bulk_create_facts

await bulk_create_facts(
    project_id=1,
    facts=[
        {"type": "architecture", "content": "Monolithic Flask application"},
        {"type": "dependency", "content": "Using Flask 2.0.1"},
        {"type": "access_control", "content": "Session-based auth with Redis"},
    ]
)
```

### Retrieving Facts

```python
from ai_tools.facts_tools import (
    get_project_facts,
    get_facts_summary,
    search_facts,
)

# Get all facts for a project
facts = await get_project_facts(project_id=1)

# Get only architecture facts
arch_facts = await get_project_facts(project_id=1, fact_type="architecture")

# Get summary with counts by type
summary = await get_facts_summary(project_id=1)

# Search facts by content
results = await search_facts(project_id=1, query="JWT")
```

---

## Best Practices

1. **Be Specific**: Include file paths, line numbers, and exact code patterns when relevant.

2. **Be Actionable**: Facts should provide enough context for follow-up security analysis.

3. **Avoid Duplicates**: Check existing facts before creating new ones with similar content.

4. **Use Correct Types**: Choose the most specific fact type for better organization and searchability.

5. **Include Evidence**: Reference specific code, configurations, or behaviors that support the fact.

6. **Note Severity**: When applicable, indicate the potential impact or severity of the finding.






