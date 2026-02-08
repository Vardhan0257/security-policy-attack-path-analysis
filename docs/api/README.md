# API Reference

Complete REST API documentation. Full API docs also available at `http://localhost:8000/docs` (Swagger UI).

---

## Endpoints Overview

| Category | Endpoint | Method | Purpose |
|----------|----------|--------|---------|
| **Health** | `/health` | GET | Health check |
| **Analysis** | `/api/v1/analyze` | POST | Sync analysis |
| **Analysis** | `/api/v1/analyze/async` | POST | Async analysis |
| **Jobs** | `/api/v1/jobs/{job_id}` | GET | Get job status |
| **Jobs** | `/api/v1/jobs/{job_id}/paths` | GET | Get analysis results |
| **Verification** | `/api/v1/verify/path` | POST | Verify single path |
| **Verification** | `/api/v1/verify/batch` | POST | Batch verify paths |
| **Verification** | `/api/v1/verify/status` | GET | Verification system status |
| **Threat** | `/api/v1/threat-score/calculate` | POST | Calculate threat score |
| **Threat** | `/api/v1/threat-score/batch` | POST | Batch threat scoring |
| **Threat** | `/api/v1/threat-score/status` | GET | Threat scoring status |
| **Cloud** | `/api/v1/cloud/sync-policies` | POST | Sync cloud policies |
| **Cloud** | `/api/v1/policies` | GET | List policies |
| **Metrics** | `/metrics` | GET | Prometheus metrics |

---

## Health & Status

### GET /health
Simple health check - always returns 200 if API is running.

**Response:**
```json
{
  "status": "healthy"
}
```

### GET /api/v1/status
Detailed status including database connectivity.

**Response:**
```json
{
  "status": "ready",
  "database": "connected",
  "timestamp": "2026-02-08T12:34:56.789012"
}
```

---

## Analysis Endpoints

### POST /api/v1/analyze
Synchronous attack path analysis. Returns results immediately.

**Request:**
```json
{
  "source_node": "internet",
  "target_node": "database",
  "context": {
    "source_ip": "external",
    "user_role": "attacker"
  },
  "max_depth": 5
}
```

**Response (200):**
```json
{
  "paths": [
    {
      "path": ["internet", "web_server", "app_server", "database"],
      "metrics": {
        "num_hops": 3,
        "total_policies": 5
      }
    }
  ],
  "total_paths_found": 1,
  "evaluation_time_ms": 234.5
}
```

---

### POST /api/v1/analyze/async
Asynchronous analysis. Returns immediately with job_id for polling.

**Request:** (same as `/analyze`)

**Response (200):**
```json
{
  "job_id": "a1b2c3d4-e5f6-4789-abcd-ef1234567890",
  "status": "pending"
}
```

**Poll Status:**
```bash
GET /api/v1/jobs/{job_id}
```

Response:
```json
{
  "job_id": "a1b2c3d4-e5f6-4789-abcd-ef1234567890",
  "status": "completed",
  "total_paths_found": 3,
  "evaluation_time_ms": 1500
}
```

**Get Results:**
```bash
GET /api/v1/jobs/{job_id}/paths
```

Response:
```json
{
  "job_id": "a1b2c3d4...",
  "paths": [
    {
      "path": ["internet", "web", "database"],
      "threat_level": "high",
      "threat_score": 8.2,
      "is_exploitable": true
    }
  ]
}
```

---

## Verification Endpoints

### POST /api/v1/verify/path
Verify if a single attack path is exploitable using Z3 SMT solver.

**Request:**
```json
{
  "path": ["internet", "web_server", "database"],
  "policies": [
    {
      "effect": "Allow",
      "conditions": [
        {
          "operator": "IpAddress",
          "key": "aws:SourceIp",
          "values": ["10.0.0.0/8"]
        }
      ]
    }
  ],
  "context": {
    "aws:SourceIp": "10.0.0.5"
  }
}
```

**Response (200):**
```json
{
  "result": "exploitable",
  "constraints_satisfied": true,
  "model": {
    "aws:SourceIp": "10 .0.0.5"
  },
  "solver_time_ms": 12.3,
  "confidence": 0.98
}
```

---

### POST /api/v1/verify/batch
Batch verify multiple paths concurrently.

**Request:**
```json
{
  "paths": [
    ["internet", "web", "db"],
    ["internet", "app", "secrets"]
  ],
  "policies": [...],
  "context": {...}
}
```

**Response (200):**
```json
{
  "results": [
    {
      "path": ["internet", "web", "db"],
      "result": "exploitable",
      "confidence": 0.95
    },
    {
      "path": ["internet", "app", "secrets"],
      "result": "satisfiable",
      "confidence": 0.87
    }
  ],
  "batch_time_ms": 45.2
}
```

---

## Threat Scoring Endpoints

### POST /api/v1/threat-score/calculate
Calculate threat score and level for an attack path.

**Request:**
```json
{
  "path": ["internet", "web_server", "database"],
  "is_exploitable": true,
  "cvss_base_score": 8.2,
  "z3_confidence": 1.0,
  "cve_count": 2,
  "max_cve_score": 8.5,
  "has_privilege_escalation": true
}
```

**Response (200):**
```json
{
  "overall_score": 8.1,
  "threat_level": "High",
  "factors": {
    "exploitability": 0.95,
    "impact": 0.89,
    "confidence": 1.0,
    "lineage": 0.7
  },
  "recommendations": [
    "Block internet access to web_server",
    "Implement MFA on database access",
    "Apply principle of least privilege"
  ]
}
```

---

### POST /api/v1/threat-score/batch
Score multiple paths in batch.

**Request:**
```json
{
  "paths": [
    {
      "path": ["internet", "web", "db"],
      "is_exploitable": true,
      "cvss_base_score": 8.2,
      "z3_confidence": 1.0
    },
    {
      "path": ["internet", "app", "secrets"],
      "is_exploitable": false,
      "cvss_base_score": 5.0,
      "z3_confidence": 0.5
    }
  ]
}
```

**Response (200):**
```json
{
  "results": [
    {
      "path": ["internet", "web", "db"],
      "overall_score": 8.1,
      "threat_level": "High"
    },
    {
      "path": ["internet", "app", "secrets"],
      "overall_score": 3.2,
      "threat_level": "Low"
    }
  ]
}
```

---

## Cloud Integration Endpoints

### POST /api/v1/cloud/sync-policies
Sync policies from cloud provider (AWS, Azure, GCP).

**Request:**
```json
{
  "provider": "aws",
  "account_name": "production",
  "what": "users"
}
```

**Response (200):**
```json
{
  "policies_synced": 145,
  "source": "aws:production",
  "timestamp": "2026-02-08T12:34:56Z"
}
```

---

### GET /api/v1/policies
List all policies in database.

**Query Parameters:**
- `provider` (optional): Filter by cloud provider (aws, azure, gcp)
- `limit` (optional): Number of results (default: 100)
- `offset` (optional): Pagination offset

**Response (200):**
```json
{
  "policies": [
    {
      "id": 1,
      "name": "AllowWebAccess",
      "provider": "aws",
      "policy_type": "iam",
      "principal": "web_users",
      "resource": "s3::mybucket",
      "actions": ["s3:GetObject", "s3:PutObject"]
    }
  ],
  "total": 245
}
```

---

## Metrics Endpoint

### GET /metrics
Prometheus metrics for monitoring.

**Format:** Prometheus text format

**Key Metrics:**
```
request_count{method="POST",path="/api/v1/analyze",status="200"} 42
request_latency_seconds_bucket{path="/api/v1/analyze",le="0.5"} 38
request_latency_seconds_sum{path="/api/v1/analyze"} 8.45
```

---

## Authentication

### Optional API Key Authentication

Set `API_KEY` environment variable to enable.

**Request with Bearer Token:**
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8000/api/v1/status
```

If `API_KEY` is not set, authentication is disabled (development mode).

---

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid request: source_node is required"
}
```

### 404 Not Found
```json
{
  "detail": "Job not found"
}
```

### 429 Too Many Requests
```json
{
  "detail": "Rate limit exceeded"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Database connection failed",
  "request_id": "abc123xyz"
}
```

---

## Rate Limiting

Default limits (if slowapi installed):
- **100 requests per minute** per IP address
- Subsequent requests return HTTP 429

---

## Examples

### Complete Analysis Workflow

```bash
# 1. Start async analysis
JOB_ID=$(curl -s -X POST http://localhost:8000/api/v1/analyze/async \
  -H "Content-Type: application/json" \
  -d '{"source_node":"internet","target_node":"database"}' \
  | jq -r '.job_id')

# 2. Poll for completion
while true; do
  STATUS=$(curl -s http://localhost:8000/api/v1/jobs/$JOB_ID | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] && break
  sleep 2
done

# 3. Get results
curl http://localhost:8000/api/v1/jobs/$JOB_ID/paths | jq '.paths'

# 4. View Prometheus metrics
curl http://localhost:8000/metrics
```

---

See [docs/](../) for full documentation.
