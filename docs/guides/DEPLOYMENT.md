# Deployment Guide

## Overview

This guide covers deploying the Security Policy Analysis API using Docker, with production-grade security hardening including:
- HTTPS/TLS encryption
- API authentication (bearer tokens)
- Rate limiting
- Prometheus metrics monitoring
- Automated security scanning (Bandit, pre-commit)

## Quick Start (Development)

### Using Docker Compose

```bash
# 1. Clone repository
git clone <repository>
cd security-policy-attack-path-analysis

# 2. Create .env file (copy from .env.example)
cp .env.example .env

# 3. Start services (PostgreSQL, API, Prometheus, Grafana)
docker-compose up -d

# 4. Check API is running
curl http://localhost:8000/health

# 5. View Prometheus metrics
curl http://localhost:8000/metrics
```

**Services:**
- API: http://localhost:8000
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000
- PostgreSQL: localhost:5432

## Production Deployment

### 1. Security Configuration

#### API Authentication

Set `API_KEY` in `.env` to enable bearer token authentication:

```bash
export API_KEY="your-secret-key-min-32-chars"
```

All requests must include the Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8000/api/v1/status
```

#### Rate Limiting

Rate limiting is enabled by default via slowapi, limiting requests per IP:
- Default: 100 requests per minute per IP
- Configurable via environment variables (future enhancement)

#### HTTPS/TLS Configuration

##### Option A: Using Nginx Reverse Proxy (Recommended)

```bash
# 1. Update docker-compose.yml to add Nginx service
# 2. Generate or provide SSL certificates
# 3. Configure Nginx with:
#    - Upstream to uvicorn API
#    - TLS termination
#    - Rate limiting
```

##### Option B: Self-Signed Certificates (Development Only)

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365

# Run with TLS
uvicorn src.api:app \
  --ssl-keyfile=key.pem \
  --ssl-certfile=cert.pem \
  --host 0.0.0.0 --port 8443
```

##### Option C: Let's Encrypt (Production)

```bash
# Use Certbot to obtain certificates
certbot certonly --standalone -d your-domain.com

# Point docker-compose to certificate files
# In docker-compose.yml:
#   volumes:
#     - /etc/letsencrypt/live/your-domain.com/fullchain.pem:/certs/cert.pem
#     - /etc/letsencrypt/live/your-domain.com/privkey.pem:/certs/key.pem
```

### 2. Database Configuration

#### PostgreSQL in Production

```bash
# Update .env
DATABASE_URL=postgresql://user:strong_password@db.example.com:5432/security_analysis

# With connection pooling (PgBouncer)
DATABASE_URL=postgresql://user:pass@pgbouncer:6432/security_analysis
```

#### Backup Strategy

```bash
# Daily backups
docker exec security_policy_db pg_dump \
  -U user security_analysis > backup_$(date +%Y%m%d).sql
```

### 3. Monitoring & Logging

#### Prometheus Metrics

Metrics available at `http://api:8000/metrics`:
- `request_count` - HTTP requests by method, path, status
- `request_latency` - Request duration in seconds

#### Grafana Dashboard

Import dashboard or create queries:
```
- Requests per second: `rate(request_count[1m])`
- Latency p95: `histogram_quantile(0.95, request_latency)`
- Error rate: `request_count{status=~"5.."} / request_count`
```

#### Logs

```bash
# View API logs
docker logs -f security_policy_api

# Export to centralized logging
# Configure /etc/docker/daemon.json for log driver
```

### 4. Security Hardening

#### Environment Hardening

```bash
# Production environment variables (.env)
ENVIRONMENT=production
LOG_LEVEL=WARNING
CORS_ORIGINS=https://your-domain.com  # Restrict CORS
CORS_CREDENTIALS=true
```

#### Pre-Commit Hooks

Enforce security checks before commits:

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Manual run
pre-commit run --all-files
```

Includes:
- Black formatting
- isort import sorting
- Ruff linting
- Bandit security scanning
- Secrets detection

#### Runtime Security Scanning

```bash
# Bandit SAST analysis
bandit -r src/ -f json -o bandit-report.json

# Truffle Hog secrets scanning
truffleflix --scan-unknown-extensions .

# Safety vulnerability check
safety check --json
```

### 5. Kubernetes Deployment (Optional)

```yaml
# Example deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-policy-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-policy-api
  template:
    metadata:
      labels:
        app: security-policy-api
    spec:
      containers:
      - name: api
        image: security-policy-api:latest
        ports:
        - containerPort: 8000
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: api-key
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secrets
              key: database-url
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Health Checks

```bash
# API health
curl http://localhost:8000/health

# Database connectivity
curl http://localhost:8000/api/v1/status

# Metrics endpoint
curl http://localhost:8000/metrics
```

## Troubleshooting

### API not starting
```bash
docker logs security_policy_api
# Check DATABASE_URL is valid
# Check API_KEY is set and exported
```

### Database connection issues
```bash
docker logs security_policy_db
# Verify PostgreSQL is running
# Check credentials in DATABASE_URL
```

### Rate limiting too aggressive
```bash
# Temporarily disable in api.py or set via env var
# Check client IP matches expected values
```

## CI/CD Pipeline

### GitHub Actions Workflow

The `.github/workflows/ci.yml` automatically:
1. Runs Bandit security scanning
2. Detects exposed secrets (detect-secrets)
3. Checks for vulnerable dependencies (safety)
4. Runs full test suite across Python 3.8-3.12
5. Builds and pushes Docker image on main branch

### Pre-Deployment Checklist

- [ ] All tests passing: `pytest`
- [ ] Bandit scan clean: `bandit -r src/`
- [ ] Pre-commit hooks pass: `pre-commit run --all-files`
- [ ] No secrets in code: `truffleflix .`
- [ ] Dependencies up to date: `safety check`
- [ ] API_KEY configured in production
- [ ] Database credentials secure
- [ ] HTTPS/TLS certificates valid
- [ ] Backups configured
- [ ] Monitoring/alerting configured

## Performance Tuning

### Database Connection Pooling

```python
# In database.py
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True  # Test connections before use
)
```

### API Workers

```bash
# Run multiple uvicorn workers (use gunicorn)
gunicorn -w 4 -k uvicorn.workers.UvicornWorker src.api:app
```

### Caching

- Graph caching: 5-minute TTL
- Analysis results: Redis optional
- Policy cache: Database

## Rollback Procedure

```bash
# If deployment fails
docker-compose down
docker pull security-policy-api:previous-tag
docker-compose up -d

# Or use git rollback
git revert <commit-hash>
docker-compose build --no-cache
docker-compose up -d
```

## Support

- GitHub Issues: [link]
- Documentation: [link]
- Security Policy: [link]
