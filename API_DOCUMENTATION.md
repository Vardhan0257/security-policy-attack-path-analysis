# API Documentation & Examples

## REST API Endpoints

### Health & Status

#### GET /health
Check if API is running.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2026-02-08T10:30:45.123456"
}
```

---

#### GET /api/v1/status
Get API and database status.

**Response:**
```json
{
  "status": "operational",
  "database": "connected",
  "policies_in_db": 1250,
  "analysis_jobs_completed": 42,
  "timestamp": "2026-02-08T10:30:45.123456"
}
```

---

### Analysis Endpoints

#### POST /api/v1/analyze
**Synchronous** attack path analysis.

**Request:**
```json
{
  "source_node": "internet",
  "target_node": "database",
  "context": {
    "source_ip": "192.168.1.100",
    "time_of_day": "business_hours",
    "user_role": "admin",
    "extra_fields": {
      "location": "us-west-2"
    }
  },
  "max_depth": 5
}
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "source_node": "internet",
  "target_node": "database",
  "paths_found": 2,
  "paths_pruned": 3,
  "evaluation_time_ms": 125.5,
  "paths": [
    {
      "nodes": ["internet", "web_server", "app_server", "database"],
      "length": 4,
      "risk_score": 85.5,
      "steps": [
        "Step 1: [internet] can reach [web_server] via network (allow_http)",
        "Step 2: [web_server] has IAM permission to [app_server] (invoke)",
        "Step 3: [app_server] has IAM permission to [database] (read)"
      ]
    }
  ],
  "created_at": "2026-02-08T10:30:45.123456"
}
```

---

#### POST /api/v1/analyze/async
**Asynchronous** attack path analysis. Returns immediately with job_id.

**Request:** Same as /api/v1/analyze

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

Then poll: `GET /api/v1/jobs/{job_id}` for results

---

#### GET /api/v1/jobs/{job_id}
Get analysis job status.

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "created_at": "2026-02-08T10:30:45.123456",
  "started_at": "2026-02-08T10:30:46.230000",
  "completed_at": "2026-02-08T10:30:47.350000",
  "paths_found": 2,
  "paths_pruned": 3,
  "error_message": null
}
```

---

#### GET /api/v1/jobs/{job_id}/paths
Get attack paths for a completed job.

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "paths": [
    {
      "nodes": ["internet", "web_server", "app_server", "database"],
      "length": 4,
      "risk_score": 85.5,
      "explanation": [
        "Step 1: [internet] can reach [web_server] via network",
        "Step 2: [web_server] has permission to [app_server]",
        "Step 3: [app_server] has permission to [database]"
      ]
    }
  ]
}
```

---

### Policy Management

#### GET /api/v1/policies
List policies in database.

**Query Parameters:**
- `provider` (optional): Filter by provider (aws, azure, gcp, generic)
- `policy_type` (optional): Filter by type (iam, firewall, network, rbac)
- `skip` (optional, default=0): Pagination offset
- `limit` (optional, default=100): Results per page (max 1000)

**Response:**
```json
{
  "total": 1250,
  "skip": 0,
  "limit": 100,
  "policies": [
    {
      "id": 1,
      "name": "admin_policy",
      "type": "iam",
      "provider": "aws",
      "principal": "admin-role",
      "resource": "arn:aws:s3:::my-bucket/*",
      "actions": ["s3:GetObject", "s3:PutObject"],
      "created_at": "2026-02-08T10:30:45.123456"
    }
  ]
}
```

---

#### POST /api/v1/cloud/sync-policies
Sync policies from cloud provider.

**Request:**
```json
{
  "provider": "aws",
  "account_name": "production-aws",
  "what": "all"
}
```

For AWS: `what` can be "users", "roles", or "all"  
For Azure: requires subscription_id in account config  
For GCP: requires project_id in account config

**Response:**
```json
{
  "account_name": "production-aws",
  "status": "sync_in_progress",
  "message": "Policy sync has been scheduled"
}
```

---

### WebSocket Endpoints

#### WS /ws/analysis/{job_id}
Real-time updates for analysis job.

**Example Usage (JavaScript):**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/analysis/550e8400-e29b-41d4-a716-446655440000');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'path') {
    console.log('Found path:', data.nodes);
  } else if (data.status === 'done') {
    console.log('Analysis complete');
  } else {
    console.log('Status:', data.status, 'Paths found:', data.paths_found);
  }
};
```

---

## Usage Examples

### Example 1: Simple Synchronous Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source_node": "internet",
    "target_node": "database",
    "context": {
      "source_ip": "external",
      "time_of_day": "business_hours"
    },
    "max_depth": 5
  }'
```

### Example 2: Async Analysis with Polling
```bash
# Start analysis
RESPONSE=$(curl -X POST http://localhost:8000/api/v1/analyze/async \
  -H "Content-Type: application/json" \
  -d '{
    "source_node": "internet",
    "target_node": "database",
    "context": {"source_ip": "external"},
    "max_depth": 5
  }')

JOB_ID=$(echo $RESPONSE | jq -r '.job_id')

# Poll for results
while true; do
  STATUS=$(curl http://localhost:8000/api/v1/jobs/$JOB_ID | jq -r '.status')
  if [ "$STATUS" = "completed" ]; then
    curl http://localhost:8000/api/v1/jobs/$JOB_ID/paths
    break
  fi
  sleep 1
done
```

### Example 3: Cloud Policy Integration
```bash
# Sync AWS policies
curl -X POST http://localhost:8000/api/v1/cloud/sync-policies \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "account_name": "prod-account",
    "what": "all"
  }'

# List imported AWS policies
curl "http://localhost:8000/api/v1/policies?provider=aws&limit=50"
```

---

## Authentication (Production)

### API Key Authentication
```bash
curl -X GET http://localhost:8000/api/v1/policies \
  -H "X-API-Key: your-secret-key"
```

### Bearer Token (OAuth 2.0)
```bash
curl -X GET http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

---

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid source or target node"
}
```

### 404 Not Found
```json
{
  "detail": "Job 550e8400-e29b-41d4-a716-446655440000 not found"
}
```

### 422 Validation Error
```json
{
  "detail": [
    {
      "loc": ["body", "max_depth"],
      "msg": "ensure this value is less than or equal to 20",
      "type": "value_error.number.not_le"
    }
  ]
}
```

### 503 Service Unavailable
```json
{
  "detail": "Database connection failed"
}
```

---

## Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Health check | <1ms | No I/O |
| Small graph analysis (10 nodes) | <10ms | Cached |
| Medium graph analysis (100 nodes) | <500ms | 5 depth limit |
| Large graph analysis (1000+ nodes) | <3s | 3 depth limit recommended |
| Policy sync (100 policies) | ~2s | Async background task |
| Database query (1000 policies) | ~50ms | Indexed queries |

---

## Interactive Documentation

Once the API is running:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

