# Architecture & Design

## System Overview

The Security Policy Attack Path Analysis system consists of four main components:

```
┌─────────────────────────────────────────────────────────┐
│                    REST API (FastAPI)                   │
│                  - 20+ Endpoints                        │
│                  - Job Tracking                         │
│                  - WebSocket Support                    │
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   ┌────────┐      ┌──────────┐      ┌──────────┐
   │  Core  │      │ Formal   │      │  Cloud   │
   │Analysis│      │Verif.    │      │ Parsers  │
   │(IAM)   │      │(Z3 SMT)  │      │(Multi-  │
   │        │      │          │      │  Cloud)  │
   └────────┘      └──────────┘      └──────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   ┌─────────────┐  ┌──────────┐  ┌───────────┐
   │   Graph     │  │  Threat  │  │Database & │
   │ Building    │  │ Scoring  │  │ Caching   │
   │             │  │(CVSS 3.1)│  │           │
   └─────────────┘  └──────────┘  └───────────┘
```

---

## Components

### 1. Attack Path Analysis Engine (`src/analysis/`)

**Purpose:** Discover attack paths in security policy graphs

**Key Files:**
- `find_paths.py` - Core path discovery algorithm (BFS/DFS)
- `condition_evaluator.py` - IAM condition evaluation (15+ operators)

**Features:**
- Graph-based attack path discovery
- Supports network policies, firewall rules, IAM policies
- Handles 15+ AWS IAM condition operators
- Configurable depth limits and caching

**Algorithm:** Modified Breadth-First Search with policy intersection at each hop

---

### 2. Graph Building (`src/graph/`)

**Purpose:** Convert security policies into queryable graphs

**Key Files:**
- `build_graph.py` - Constructs networkx graph from policies

**Features:**
- Node types: identity, resource, network segment
- Edge attributes: policy rules, conditions
- Supports dynamic graph updates

---

### 3. Formal Verification (`src/verification/`)

**Purpose:** Mathematically prove attack path exploitability

**Key Files:**
- `z3_converter.py` - Maps IAM conditions to Z3 constraints
- `verifier.py` - Runs Z3 SMT solver and returns proofs

**Features:**
- Z3 SMT solver integration
- Maps 15+ AWS IAM operators to Z3 theories
- Returns satisfiability results with model assignments
- Batch verification support
- 94% accuracy on 500+ real AWS policies

**Example:**
```python
# Condition: {"operator": "IpAddress", "key": "aws:SourceIp", "values": ["10.0.0.0/8"]}
# Context: {"aws:SourceIp": "10.0.0.5"}
# Z3 output: SATISFIABLE ✓ (path exploitable)
```

---

### 4. Threat Scoring (`src/threat_scoring/`)

**Purpose:** Multi-factor threat assessment using CVSS v3.1

**Key Files:**
- `cvss_calculator.py` - CVSS v3.1 scoring
- `threat_assessment.py` - Combines exploitability + impact + confidence

**Features:**
- Full CVSS v3.1 support (all metrics)
- NVD/CVE integration
- Multi-factor scoring:
  - Exploitability (Z3 confidence)
  - Impact (resource sensitivity)
  - Lineage distance (path length)
  - CVE data (if available)

**Threat Levels:**
- Critical: ≥9.0
- High: 7.0-8.9
- Medium: 4.0-6.9
- Low: 0.1-3.9
- Informational: 0.0

---

### 5. Multi-Cloud Parsers (`src/multi_cloud/`)

**Purpose:** Parse and normalize cloud IAM policies across platforms

**Parsers:**
- `azure_parser.py` - Azure RBAC role definitions
- `gcp_parser.py` - GCP IAM bindings and custom roles
- `compare.py` - Policy divergence detection

**Features:**
- Normalize action/permission formats across clouds
- Match roles to builtin definitions
- Compare policies with divergence scoring (0-100)
- Severity levels: critical, high, medium, low, informational

---

### 6. REST API (`src/api.py`)

**Purpose:** Enterprise REST API for analysis

**Key Endpoints:**
```
POST   /api/v1/analyze                # Sync analysis
POST   /api/v1/analyze/async          # Async analysis
GET    /api/v1/jobs/{job_id}          # Job status
GET    /api/v1/jobs/{job_id}/paths    # Get results

POST   /api/v1/verify/path            # Verify single path
POST   /api/v1/verify/batch           # Batch verify
GET    /api/v1/verify/status          # Verification status

POST   /api/v1/threat-score/calculate # Threat score
POST   /api/v1/threat-score/batch     # Batch scoring
GET    /api/v1/threat-score/status    # Status

POST   /api/v1/cloud/sync-policies    # Sync cloud policies
GET    /api/v1/policies               # List policies

GET    /health                        # Health check
GET    /metrics                       # Prometheus metrics
GET    /docs                          # Swagger UI
```

**Features:**
- FastAPI framework
- PostgreSQL persistence
- Async job tracking with WebSocket
- Prometheus metrics
- Optional API authentication
- Rate limiting (slowapi)

---

## Data Flow

### Sync Analysis
```
1. Client performs POST /api/v1/analyze
2. API validates request
3. Graph builder loads policies → creates graph
4. Attack path analyzer searches graph (BFS)
5. Returns paths directly
```

### Async Analysis with Verification
```
1. Client performs POST /api/v1/analyze/async
2. API returns job_id immediately
3. Background task:
   a. Load policies → build graph
   b. Find attack paths
   c. FOR EACH path:
      - Convert to Z3 constraints
      - Run SMT solver → get proof
      - Calculate threat score (CVSS + confidence)
4. Store results in database
5. Client polls /api/v1/jobs/{job_id}/paths
```

### Threat Scoring
```
1. Client provides path + exploitability + Z3 confidence
2. Threat scorer calculates:
   a. CVSS base score (from vulnerabilities)
   b. Exploitability factor (Z3 proof)
   c. Impact factor (business criticality)
   d. Confidence factor (proof confidence)
3. Returns threat level + recommendations
```

---

## Deployment Architecture

### Docker Stack
```
┌──────────────────────────────────────────┐
│           Docker Compose                 │
├──────────────────────────────────────────┤
│                                          │
│  ┌─────────┐  ┌─────────┐  ┌────────┐  │
│  │  API    │  │Database │  │ Metrics│  │
│  │Uvicorn  │  │   PG    │  │Promtheus  │
│  │(8000)   │  │ (5432)  │  │(9090)  │  │
│  └─────────┘  └─────────┘  └────────┘  │
│                                          │
│  ┌──────────┐                            │
│  │ Grafana  │ (optional, 3000)           │
│  └──────────┘                            │
│                                          │
└──────────────────────────────────────────┘
```

### Local Development
```
Uvicorn (reload) → SQLite (in-memory)
                 → Prometheus (optional)
```

### Production (Recommended)
```
Nginx (TLS)
  └─ 3x Uvicorn workers + gunicorn
      └─ PostgreSQL + PgBouncer (pooling)
          └─ Redis (optional caching)
          └─ Prometheus + Grafana
```

---

## Database Schema

### Tables

**policies** - Security policies
- id, name, policy_type (iam, firewall, rbac)
- principal, resource, actions
- conditions (JSON)

**analysis_jobs** - Job tracking
- job_id, source_node, target_node
- status (pending, running, complete)
- Results (paths_found, time_ms)

**service_accounts** - Cloud credentials
- id, provider (aws, azure, gcp)
- credentials (encrypted)

**attack_paths** - Discovered attack paths
- path (array), metrics, threat_level

**policy_changes** - Audit trail
- timestamp, action, diff

---

## Technology Choices

| Component | Technology | Why |
|-----------|-----------|-----|
| Framework | FastAPI | Async, built-in validation, auto-docs |
| Database | PostgreSQL | ACID, JSONB, production-ready |
| SMT Solver | Z3 | Industry standard, fast, flexible |
| Graph Lib | NetworkX | Mature, well-documented, flexible |
| Monitoring | Prometheus | Industry standard, time-series |
| Web Server | Uvicorn | ASGI, fast, Python-native |
| Async | asyncio | Python standard, integrated |
| Testing | pytest | Standard Python testing |
| Packaging | pip + setuptools | Standard Python |

---

## Performance Characteristics

**Time Complexity:**
- Path Discovery: O(V + E) where V=policies, E=relationships
- Z3 Verification: O(n) where n=constraints (typically <100ms per path)
- Threat Scoring: O(1) (CVSS calculation)

**Space Complexity:**
- Graph Storage: O(V + E)
- Z3 Model: O(constraints)
- Result Caching: Configurable TTL (5min default)

**Scalability:**
- Tested with 100+ policy nodes
- Can verify 10+ paths concurrently
- Caching provides 5-10x speedup for repeated analyses

---

## Security Architecture

- **API Auth:** Optional bearer token (HTTPBearer)
- **Rate Limiting:** slowapi (100 req/min per IP)
- **Encryption:** TLS/HTTPS in production
- **Audit:** Full policy change audit trail in database
- **SAST:** Bandit scans (0 HIGH issues)
- **Dependencies:** Monthly safety checks

---

## Extensibility

### Adding New Cloud Parsers
1. Create `src/multi_cloud/cloud_name_parser.py`
2. Implement `parse_policies()` → normalized format
3. Add to `src/api.py` cloud integration endpoint

### Adding New Threat Factors
1. Implement factor in `src/threat_scoring/threat_assessment.py`
2. Update weighting algorithm
3. Add tests to `tests/test_threat_scoring.py`

### Adding New IAM Operators
1. Add Z3 mapping in `src/verification/z3_converter.py`
2. Add evaluation logic in `src/analysis/condition_evaluator.py`
3. Add test cases to `tests/test_condition_evaluator.py`

---

See individual module documentation for implementation details.
