# AI-Powered Security Analysis System

An autonomous security analysis system built on Large Language Models (LLMs) and AI agents. Designed for analyzing any codebase with deep expertise in blockchain and decentralized systems.

---

## System Overview

```mermaid
flowchart TB
    subgraph Input
        CB[Codebase]
    end
    
    subgraph "Phase 1: Fact Gathering"
        AGENT1[AI Fact Gathering Agent]
        FACTS[(Facts Knowledge Base)]
    end
    
    subgraph "Phase 2: Threat Modeling"
        AGENT2[AI Threat Modeling Agent]
        THREATS[(Threat Models)]
    end
    
    subgraph "Phase 3: Vulnerability Detection"
        AGENT3[AI Security Analysis Agent]
        FINDINGS[(Security Findings)]
    end
    
    subgraph "Phase 4: Validation"
        AGENT4[AI Validation Agent]
        VALIDATED[(Validated Findings)]
    end
    
    CB --> AGENT1
    AGENT1 --> FACTS
    FACTS --> AGENT2
    AGENT2 --> THREATS
    FACTS --> AGENT3
    THREATS --> AGENT3
    AGENT3 --> FINDINGS
    FACTS --> AGENT4
    FINDINGS --> AGENT4
    AGENT4 --> VALIDATED
```

---

## AI Agent Architecture

The system uses specialized LLM-powered agents for each phase of analysis:

```mermaid
flowchart LR
    subgraph "LLM Foundation"
        LLM[Large Language Model]
    end
    
    subgraph "Specialized Agents"
        A1[Fact Gathering Agent]
        A2[Threat Modeling Agent]
        A3[Security Analysis Agent]
        A4[Validation Agent]
    end
    
    subgraph "Agent Toolkits"
        T1[Code Reading Tools]
        T2[Fact Creation Tools]
        T3[Finding Tools]
        T4[Validation Tools]
    end
    
    LLM --> A1 & A2 & A3 & A4
    A1 --> T1 & T2
    A2 --> T1 & T2
    A3 --> T1 & T3
    A4 --> T1 & T4
```

### Agent Characteristics

| Agent | Purpose | LLM Role |
|-------|---------|----------|
| **Fact Gatherer** | Extracts structured knowledge from code | Understands code patterns, identifies security-relevant constructs |
| **Threat Modeler** | Applies relevant threat models | Maps attack vectors based on codebase type and architecture |
| **Security Analyzer** | Detects vulnerabilities using context | Combines code analysis with facts and threat models |
| **Validator** | Verifies findings with evidence | Cross-references findings against facts to reduce false positives |

---

## The Four Phases

### Phase 1: Fact Gathering
AI agents analyze the codebase to extract structured facts about architecture, attack surfaces, and security properties.

### Phase 2: Threat Modeling  
Using gathered facts, agents apply relevant threat models based on the codebase type and identified patterns.

### Phase 3: Vulnerability Detection
Security analysis agents scan the code using facts and threat models as context for accurate detection.

### Phase 4: Validation
Validation agents verify each finding against the facts knowledge base to confirm exploitability.

---

## Detailed Flow with Feedback Loops

```mermaid
flowchart TD
    subgraph "1. CODEBASE INGESTION"
        A[Load Codebase] --> B[Parse Code Structure]
        B --> C[Identify Components]
        C --> D[Map Dependencies]
    end
    
    subgraph "2. AI FACT GATHERING"
        D --> E{AI Agent Analyzes Each Fact Type}
        E --> F1[Architecture]
        E --> F2[Attack Surface]
        E --> F3[Dependencies]
        E --> F4[Data/Asset Flow]
        E --> F5[Access Control]
        E --> F6[Dangerous Patterns]
        E --> F7[Input Validation]
        E --> F8[Cryptography]
        E --> F9[State & Business Logic]
        E --> F10[External Interactions]
        E --> F11[Threat Indicators]
        
        F1 & F2 & F3 & F4 & F5 & F6 & F7 & F8 & F9 & F10 & F11 --> G[(Facts Knowledge Base)]
    end
    
    subgraph "3. AI THREAT MODELING"
        G -.->|Facts inform threat analysis| H[AI Agent Loads Threat Models]
        H --> I{Apply Relevant Threat Categories}
        I --> J1[Protocol-Specific Threats]
        I --> J2[Language-Specific Threats]
        I --> J3[Framework Threats]
        I --> J4[Cryptographic Threats]
        I --> J5[Infrastructure Threats]
        I --> J6[Business Logic Threats]
        
        J1 & J2 & J3 & J4 & J5 & J6 --> K[Generate Attack Scenarios]
        K --> L[(Active Threat Models)]
    end
    
    subgraph "4. AI SECURITY ANALYSIS"
        G -.->|Facts guide analysis| M[AI Security Agent]
        L --> M
        M --> N[LLM-Powered Code Analysis]
        N --> O[Pattern & Vulnerability Detection]
        O --> P[Context-Aware Finding Generation]
        P --> Q[(Security Findings)]
    end
    
    subgraph "5. AI VALIDATION"
        Q --> R[AI Validation Agent]
        G -.->|Facts provide evidence| R
        R --> S[Cross-Reference with Facts]
        S --> T{Validation Decision}
        T -->|Exploitable| U[Confirmed Vulnerability]
        T -->|Not Exploitable| V[False Positive]
        T -->|Uncertain| W[Manual Review]
        U & V & W --> X[(Validated Findings)]
    end
    
    style G fill:#0dcaf0,color:#000
    style L fill:#ffc107,color:#000
    style Q fill:#dc3545,color:#fff
    style X fill:#198754,color:#fff
```

---

## Fact Types

The AI agents gather 11 distinct types of facts about the codebase:

### 1. Architecture Facts
**Purpose:** Understand the system's structural design

| Aspect | Description |
|--------|-------------|
| Components | Main modules, services, contracts, and their responsibilities |
| Design Patterns | Architectural patterns used (proxy, factory, singleton, etc.) |
| Layers | Separation of concerns, component hierarchy |
| Trust Boundaries | Boundaries between trusted and untrusted components |
| Inter-Component Communication | How components interact with each other |

### 2. Attack Surface Facts
**Purpose:** Identify all entry points and exposed interfaces

| Aspect | Description |
|--------|-------------|
| Public Interfaces | Exposed functions, endpoints, APIs |
| User Inputs | All points where external input is accepted |
| Callback Handlers | Functions triggered by external events |
| Default Handlers | Fallback behaviors, catch-all handlers |
| Cross-System Entry | Entry points from external systems |

### 3. Dependency Facts
**Purpose:** Catalog external dependencies and libraries

| Aspect | Description |
|--------|-------------|
| Direct Dependencies | Libraries and packages directly used |
| External Systems | External protocols, services, systems |
| Interface Dependencies | Standards and interfaces implemented |
| Inherited Components | Base components and their properties |
| Version Information | Dependency versions for vulnerability matching |

### 4. Data/Asset Flow Facts
**Purpose:** Track how data and value move through the system

| Aspect | Description |
|--------|-------------|
| Value Transfers | Movement of assets, tokens, funds |
| Sensitive Data | PII, credentials, secrets locations |
| Accounting Logic | Balance tracking, state calculations |
| Fee Mechanisms | Protocol fees, charges, deductions |
| Flow Paths | Complete paths from source to sink |

### 5. Access Control Facts
**Purpose:** Document permission and authorization systems

| Aspect | Description |
|--------|-------------|
| Role System | Defined roles and their capabilities |
| Permission Checks | Where and how permissions are verified |
| Multi-Party Requirements | Multi-sig, threshold, consensus requirements |
| Emergency Controls | Pause mechanisms, circuit breakers |
| Privilege Management | How privileges are granted/revoked |

### 6. Dangerous Pattern Facts
**Purpose:** Identify potentially unsafe operations

| Aspect | Description |
|--------|-------------|
| Dynamic Execution | Dynamic code execution, eval, reflection |
| External Calls | Calls to untrusted external components |
| Low-Level Operations | Direct memory access, unsafe operations |
| Destructive Operations | Delete, destroy, irreversible actions |
| Unchecked Operations | Operations without safety checks |

### 7. Input Validation Facts
**Purpose:** Document input handling and sanitization

| Aspect | Description |
|--------|-------------|
| Validation Points | Where inputs are validated |
| Validation Rules | What checks are applied |
| Bounds Checking | Min/max limits, range validation |
| Format Validation | Type checks, format requirements |
| Signature Validation | Cryptographic signature verification |

### 8. Cryptography Facts
**Purpose:** Catalog cryptographic implementations

| Aspect | Description |
|--------|-------------|
| Algorithms Used | Encryption, hashing, signing algorithms |
| Key Management | Key generation, storage, rotation |
| Proof Systems | Merkle proofs, zero-knowledge, commitments |
| Randomness Sources | How randomness is generated |
| Signature Schemes | Digital signature implementations |

### 9. State & Business Logic Facts
**Purpose:** Understand application state and logic flows

| Aspect | Description |
|--------|-------------|
| State Variables | Critical state and their meaning |
| Invariants | Conditions that must always hold |
| State Transitions | Valid state changes, lifecycle |
| Business Rules | Core logic constraints and rules |
| Concurrency Patterns | Reentrancy guards, mutex, locks |

### 10. External Interaction Facts
**Purpose:** Map all external system dependencies

| Aspect | Description |
|--------|-------------|
| External Data Sources | Oracles, APIs, data feeds |
| Protocol Integrations | Third-party protocol interactions |
| Cross-System Communication | Messages, events, callbacks |
| External Services | Cloud services, infrastructure dependencies |
| Trust Assumptions | What external systems are trusted |

### 11. Threat Indicator Facts
**Purpose:** Identify patterns suggesting security concerns

| Aspect | Description |
|--------|-------------|
| Vulnerability Patterns | Code patterns matching known vulnerabilities |
| Manipulation Vectors | Patterns susceptible to manipulation |
| Centralization Risks | Single points of failure |
| Front-Running Risk | Operations vulnerable to ordering attacks |
| Configuration Issues | Insecure defaults, misconfigurations |

---

## Threat Categories

```mermaid
flowchart TB
    subgraph "Protocol Threats"
        D1[Flash/Instant Attack Vectors]
        D2[Price/Data Manipulation]
        D3[Front-Running/MEV]
        D4[Liquidity/Drain Attacks]
        D5[Infinite Mint/Burn]
    end
    
    subgraph "Code-Level Threats"
        S1[Reentrancy]
        S2[Access Control Bypass]
        S3[Integer Overflow/Underflow]
        S4[Injection Attacks]
        S5[Memory/Storage Issues]
    end
    
    subgraph "Integration Threats"
        B1[Message Replay]
        B2[Trust Boundary Violations]
        B3[Double Spend/Processing]
        B4[Fake Data/Token Injection]
        B5[Timing Attacks]
    end
    
    subgraph "Governance Threats"
        G1[Governance Manipulation]
        G2[Timelock Bypass]
        G3[Vote/Consensus Manipulation]
        G4[Privilege Escalation]
    end
```

---

## Feedback Loop 1: Facts → Threat Modeling

```mermaid
flowchart LR
    subgraph "Facts from AI Agent"
        F1[Architecture Facts]
        F2[Attack Surface Facts]
        F3[External Interaction Facts]
        F4[Data/Asset Flow Facts]
        F5[Access Control Facts]
    end
    
    subgraph "AI Threat Modeling Agent"
        TM[Select Relevant Threats]
        TC[Categorize by System Type]
        TS[Generate Attack Scenarios]
    end
    
    F1 -->|"System type → threat category"| TM
    F2 -->|"Entry points → attack vectors"| TC
    F3 -->|"External deps → manipulation risks"| TC
    F4 -->|"Value handling → drain scenarios"| TS
    F5 -->|"Access controls → bypass vectors"| TS
    
    TM --> TC --> TS
```

**How AI Uses Facts for Threat Modeling:**

| Fact Type | AI Agent Application |
|-----------|---------------------|
| Architecture | Identifies system type → selects relevant threat models |
| Attack Surface | Maps all entry points for enumeration of attack vectors |
| External Interactions | Dependencies → adds manipulation/trust threats |
| Data/Asset Flow | Value patterns → enables drain attack modeling |
| Access Control | Privileged functions → adds escalation scenarios |

---

## Feedback Loop 2: Facts → Finding Validation

```mermaid
flowchart LR
    subgraph "Finding from Security Agent"
        FINDING[Potential Vulnerability]
    end
    
    subgraph "Facts for Validation"
        FC1[State & Logic Facts]
        FC2[Access Control Facts]
        FC3[External Interaction Facts]
        FC4[Dangerous Pattern Facts]
    end
    
    subgraph "AI Validation Decision"
        VAL{Validate with Evidence}
        TP[Confirmed Exploitable]
        FP[Protected/Not Exploitable]
        NR[Needs Context Review]
    end
    
    FINDING --> VAL
    FC1 -->|"Check guards/protections"| VAL
    FC2 -->|"Check access restrictions"| VAL
    FC3 -->|"Check call targets"| VAL
    FC4 -->|"Check safety patterns"| VAL
    
    VAL --> TP
    VAL --> FP
    VAL --> NR
```

**How AI Uses Facts for Validation:**

| Fact Type | AI Validation Application |
|-----------|--------------------------|
| State & Logic | Checks if protection mechanisms exist |
| Access Control | Verifies if vulnerable function is actually callable |
| Data/Asset Flow | Confirms if value can actually be extracted |
| Dangerous Patterns | Cross-references with known safe patterns |
| Input Validation | Checks if attack inputs would pass validation |

---

## AI Agent Interaction Flow

```mermaid
sequenceDiagram
    participant User
    participant System
    participant FactAgent as Fact Gathering Agent (LLM)
    participant ThreatAgent as Threat Modeling Agent (LLM)
    participant ScanAgent as Security Analysis Agent (LLM)
    participant ValAgent as Validation Agent (LLM)
    participant KB as Knowledge Base
    
    User->>System: Submit Codebase
    
    System->>FactAgent: Analyze Codebase
    loop For Each Fact Type
        FactAgent->>FactAgent: LLM analyzes code
        FactAgent->>KB: Store extracted facts
    end
    
    System->>ThreatAgent: Generate Threat Models
    ThreatAgent->>KB: Load facts
    ThreatAgent->>ThreatAgent: LLM maps threats to system
    ThreatAgent->>KB: Store threat models
    
    System->>ScanAgent: Detect Vulnerabilities
    ScanAgent->>KB: Load facts + threats
    loop For Each Component
        ScanAgent->>ScanAgent: LLM analyzes with context
        ScanAgent->>KB: Store findings
    end
    
    System->>ValAgent: Validate Findings
    loop For Each Finding
        ValAgent->>KB: Load finding + related facts
        ValAgent->>ValAgent: LLM validates with evidence
        ValAgent->>KB: Update finding status
    end
    
    System->>User: Present Validated Results
```

---

## Finding Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Detected: AI Agent detects issue
    
    Detected --> Pending: Queued for validation
    Pending --> Validating: AI Validation Agent starts
    
    Validating --> Confirmed: AI confirms exploitability
    Validating --> FalsePositive: AI determines not exploitable
    Validating --> NeedsReview: AI uncertain, needs human
    
    NeedsReview --> Confirmed: Auditor confirms
    NeedsReview --> FalsePositive: Auditor dismisses
    NeedsReview --> Acknowledged: Risk accepted
    
    Confirmed --> Remediated: Fix deployed
    Confirmed --> Acknowledged: Risk accepted
    
    FalsePositive --> [*]
    Remediated --> [*]
    Acknowledged --> [*]
```

---

## Process Summary

| Phase | AI Agent Role | Input | Output |
|-------|---------------|-------|--------|
| **Fact Gathering** | LLM extracts structured knowledge from code | Codebase | 11 Fact Types |
| **Threat Modeling** | LLM maps relevant threats to system | Facts + Threat Library | Active Threats |
| **Security Analysis** | LLM detects vulnerabilities with full context | Code + Facts + Threats | Findings |
| **Validation** | LLM verifies exploitability using facts as evidence | Findings + Facts | Validated Results |

---

## Key Principles

1. **LLM-Powered Analysis** — All phases use Large Language Models that understand code patterns and security concepts

2. **Facts as Context** — The facts knowledge base provides rich context that enables more accurate AI analysis

3. **Threat Model Flexibility** — Threat models are selected based on codebase type and identified patterns

4. **AI Agent Autonomy** — Each agent operates autonomously with specialized tools for their specific task

5. **Evidence-Based Validation** — The validation agent cross-references findings against facts, reducing false positives through AI reasoning

6. **Iterative Improvement** — Agents can re-analyze as code is updated, maintaining accurate knowledge base
