"""
FastAPI REST API for security policy analysis.

Provides endpoints for:
- Policy submission and analysis
- Job tracking and results
- Real-time analysis updates
- Cloud integration
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, Response
try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:
    Counter = None
    Histogram = None
    generate_latest = None
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import uuid
import logging
import asyncio
import json
from datetime import datetime
import time

from src.database import get_db, SessionLocal, init_db
from src.database import ServiceAccount, Policy, AnalysisJob, AttackPath, AnalysisCache
from src.analysis.find_paths import AttackPathAnalyzer
from src.graph.build_graph import build_graph
from src.cloud_parsers import parse_cloud_policies
from src.verification import Z3Verifier, VerificationResult, ProofResult
from src.threat_scoring import (
    CVSSCalculator,
    CVSSScore,
    ThreatAssessment,
    PathThreatScorer,
    PathThreatScore,
    ThreatLevel,
)

logger = logging.getLogger(__name__)

# Prometheus metrics (optional)
if Counter is not None and Histogram is not None:
    REQUEST_COUNT = Counter('api_requests_total', 'Total API requests', ['method', 'endpoint', 'http_status'])
    REQUEST_LATENCY = Histogram('api_request_latency_seconds', 'API request latency', ['endpoint'])
else:
    REQUEST_COUNT = None
    REQUEST_LATENCY = None

# ============================================================================
# Request/Response Models
# ============================================================================

class ContextModel(BaseModel):
    """Execution context for path analysis."""
    source_ip: Optional[str] = None
    time_of_day: Optional[str] = None
    user_role: Optional[str] = None
    extra_fields: Optional[Dict[str, str]] = None
    
    class Config:
        examples = [{
            "source_ip": "192.168.1.100",
            "time_of_day": "business_hours",
            "user_role": "admin"
        }]


class AnalysisRequest(BaseModel):
    """Request for attack path analysis."""
    source_node: str = Field(..., description="Starting node")
    target_node: str = Field(..., description="Target node")
    context: ContextModel
    max_depth: int = Field(5, ge=1, le=20)
    
    class Config:
        examples = [{
            "source_node": "internet",
            "target_node": "database",
            "context": {
                "source_ip": "external",
                "time_of_day": "business_hours"
            },
            "max_depth": 5
        }]


class PathExplanation(BaseModel):
    """Explanation for a single path."""
    nodes: List[str]
    length: int
    risk_score: float
    steps: List[str]


class AnalysisResponse(BaseModel):
    """Response with analysis results."""
    job_id: str
    status: str
    source_node: str
    target_node: str
    paths_found: int
    paths_pruned: int
    evaluation_time_ms: float
    paths: List[PathExplanation]
    created_at: str


class AnalysisJobResponse(BaseModel):
    """Status of an analysis job."""
    job_id: str
    status: str
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    paths_found: int
    paths_pruned: int
    error_message: Optional[str]


class CloudPolicyRequest(BaseModel):
    """Request to sync policies from cloud provider."""
    provider: str  # aws, azure, gcp
    account_name: str
    what: Optional[str] = "all"  # For AWS: users, roles, all


class PolicyResponse(BaseModel):
    """Policy in database format."""
    id: int
    name: str
    policy_type: str
    provider: str
    principal: str
    resource: str
    actions: List[str]
    conditions: Optional[Dict]


# ============================================================================
# Phase 3: Z3 Formal Verification Models
# ============================================================================

class VerificationRequest(BaseModel):
    """Request to formally verify an attack path."""
    path: List[str] = Field(..., description="Attack path nodes")
    policies: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Security policies to verify against (if None, uses imported policies)"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Execution context (source_ip, username, etc.)"
    )
    
    class Config:
        examples = [{
            "path": ["internet", "web_server", "database"],
            "policies": [
                {
                    "effect": "Allow",
                    "conditions": [
                        {
                            "operator": "StringEquals",
                            "key": "aws:username",
                            "values": ["app_user"]
                        }
                    ]
                }
            ],
            "context": {
                "source_ip": "192.168.1.100",
                "aws:username": "app_user"
            }
        }]


class ProofExplanation(BaseModel):
    """Formal proof result for a path."""
    path: List[str]
    result: str  # exploitable, blocked, unknown
    constraints_satisfied: Optional[bool]
    num_constraints: int
    solver_time_ms: float
    explanation: str
    constraints_used: Optional[List[str]] = None
    model: Optional[Dict[str, Any]] = None  # Z3 model if exploitable


class VerificationResponse(BaseModel):
    """Response with formal verification results."""
    job_id: str
    path: List[str]
    result: str  # exploitable, blocked, unknown
    constraints_satisfied: Optional[bool]
    num_constraints: int
    solver_time_ms: float
    explanation: str
    created_at: str
    constraints_used: Optional[List[str]] = None


class BatchVerificationRequest(BaseModel):
    """Request to verify multiple paths."""
    paths: List[List[str]]
    policies: Optional[List[Dict[str, Any]]] = None
    context: Dict[str, Any] = Field(default_factory=dict)


# Threat Scoring Models
class ThreatScoreRequest(BaseModel):
    """Request to score threat level of attack path."""
    path: List[str]
    is_exploitable: bool
    cvss_base_score: Optional[float] = None
    z3_confidence: float = 1.0
    cve_count: int = 0
    max_cve_score: Optional[float] = None
    has_authentication_bypass: bool = False
    has_privilege_escalation: bool = False


class ThreatComponent(BaseModel):
    """Individual component of threat score."""
    name: str
    value: float
    weight: float
    weighted_value: float
    description: str


class ThreatScoreResponse(BaseModel):
    """Response with threat score assessment."""
    path: List[str]
    overall_score: float
    threat_level: str
    exploitability_score: float
    impact_score: float
    lineage_score: float
    confidence_score: float
    cve_count: int
    max_cve_score: Optional[float] = None
    components: List[ThreatComponent]
    recommendations: List[str]
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class MultipleThreatScoresRequest(BaseModel):
    """Request to score multiple paths."""
    paths: List[Dict[str, Any]]


class MultipleThreatScoresResponse(BaseModel):
    """Response with multiple threat scores."""
    scores: List[ThreatScoreResponse]
    total_paths: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class CVSSVectorRequest(BaseModel):
    """Request to calculate CVSS score."""
    vector_string: Optional[str] = None
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"


class CVSSVectorResponse(BaseModel):
    """Response with CVSS score."""
    base_score: float
    temporal_score: float
    severity: str
    vector_string: str
    severity_color: str


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Security Policy Analysis API",
    description="Enterprise-grade attack path analysis with cloud integration",
    version="2.0.0"
)

# Add CORS middleware for production deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prometheus_middleware(request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    try:
        if REQUEST_COUNT is not None:
            REQUEST_COUNT.labels(request.method, request.url.path, response.status_code).inc()
        if REQUEST_LATENCY is not None:
            REQUEST_LATENCY.labels(request.url.path).observe(elapsed)
    except Exception:
        pass
    return response

# Global cache for graph (loaded once)
_graph_cache = None
_graph_cache_time = None


def get_cached_graph():
    """Get or build security graph (with caching)."""
    global _graph_cache, _graph_cache_time
    
    # Rebuild every 5 minutes
    if _graph_cache is None or (time.time() - _graph_cache_time > 300):
        logger.info("Rebuilding security graph...")
        _graph_cache = build_graph()
        _graph_cache_time = time.time()
    
    return _graph_cache


# ============================================================================
# Health Check Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/status")
async def api_status(db: Session = Depends(get_db)):
    """API status with database info."""
    try:
        # Test database connection
        policy_count = db.query(Policy).count()
        job_count = db.query(AnalysisJob).count()
        
        return {
            "status": "operational",
            "database": "connected",
            "policies_in_db": policy_count,
            "analysis_jobs_completed": job_count,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        raise HTTPException(status_code=503, detail="Database connection failed")


@app.get("/metrics")
def metrics_endpoint():
    """Prometheus metrics endpoint."""
    if generate_latest is None:
        return Response(content=b"", media_type="text/plain")
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# ============================================================================
# Analysis Endpoints
# ============================================================================

@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_attack_paths(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Analyze attack paths synchronously.
    
    For large graphs, consider using POST /api/v1/analyze/async instead.
    """
    job_id = str(uuid.uuid4())
    
    try:
        # Build context dictionary
        context = {
            "source_ip": request.context.source_ip,
            "time_of_day": request.context.time_of_day,
            "user_role": request.context.user_role,
        }
        if request.context.extra_fields:
            context.update(request.context.extra_fields)
        
        # Get cached graph
        graph = get_cached_graph()
        
        # Run analysis
        analyzer = AttackPathAnalyzer(graph, context, request.max_depth)
        
        start_time = time.time()
        paths = analyzer.find_attack_paths(
            request.source_node,
            request.target_node,
            use_cache=True
        )
        elapsed_ms = (time.time() - start_time) * 1000
        
        metrics = analyzer.get_metrics()
        
        # Format paths
        path_explanations = []
        for path in paths:
            explanation_steps = analyzer.explain_path(path)
            score = analyzer.score_path(path)
            
            path_explanations.append(PathExplanation(
                nodes=path,
                length=len(path),
                risk_score=score,
                steps=explanation_steps
            ))
        
        # Sort by risk score
        path_explanations.sort(key=lambda x: x.risk_score, reverse=True)
        
        # Save job to database
        job = AnalysisJob(
            job_id=job_id,
            source_node=request.source_node,
            target_node=request.target_node,
            context=context,
            max_depth=request.max_depth,
            status="completed",
            total_paths_found=metrics["total_paths_found"],
            paths_pruned=metrics["paths_pruned"],
            evaluation_time_ms=elapsed_ms,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        db.add(job)
        db.commit()
        
        # Save paths
        for path_exp in path_explanations:
            attack_path = AttackPath(
                job_id=job.id,
                path_nodes=path_exp.nodes,
                path_length=path_exp.length,
                risk_score=path_exp.risk_score,
                explanation=path_exp.steps
            )
            db.add(attack_path)
        db.commit()
        
        logger.info(f"Analysis {job_id} completed: {len(paths)} paths found")
        
        return AnalysisResponse(
            job_id=job_id,
            status="completed",
            source_node=request.source_node,
            target_node=request.target_node,
            paths_found=metrics["total_paths_found"],
            paths_pruned=metrics["paths_pruned"],
            evaluation_time_ms=elapsed_ms,
            paths=path_explanations,
            created_at=datetime.utcnow().isoformat()
        )
        
    except ValueError as e:
        logger.error(f"Invalid request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/v1/analyze/async")
async def analyze_async(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Analyze attack paths asynchronously.
    
    Returns immediately with job_id. Poll /api/v1/jobs/{job_id} for results.
    """
    job_id = str(uuid.uuid4())
    
    # Create job record
    job = AnalysisJob(
        job_id=job_id,
        source_node=request.source_node,
        target_node=request.target_node,
        context=request.context.dict(),
        max_depth=request.max_depth,
        status="pending"
    )
    db.add(job)
    db.commit()
    
    # Schedule async task
    background_tasks.add_task(
        _run_analysis_background,
        job_id=job_id,
        request=request
    )
    
    logger.info(f"Async analysis {job_id} scheduled")
    
    return {"job_id": job_id, "status": "pending"}


async def _run_analysis_background(job_id: str, request: AnalysisRequest):
    """Background task for async analysis."""
    db = SessionLocal()
    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            logger.error(f"Job {job_id} not found")
            return
        
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()
        
        # Run analysis (same as sync)
        context = request.context.dict()
        graph = get_cached_graph()
        analyzer = AttackPathAnalyzer(graph, context, request.max_depth)
        
        start_time = time.time()
        paths = analyzer.find_attack_paths(
            request.source_node,
            request.target_node
        )
        elapsed_ms = (time.time() - start_time) * 1000
        
        metrics = analyzer.get_metrics()
        
        # Update job
        job.status = "completed"
        job.total_paths_found = metrics["total_paths_found"]
        job.paths_pruned = metrics["paths_pruned"]
        job.evaluation_time_ms = elapsed_ms
        job.completed_at = datetime.utcnow()
        db.commit()
        
        # Save paths
        for path in paths:
            score = analyzer.score_path(path)
            attack_path = AttackPath(
                job_id=job.id,
                path_nodes=path,
                path_length=len(path),
                risk_score=score,
                explanation=analyzer.explain_path(path)
            )
            db.add(attack_path)
        db.commit()
        
        logger.info(f"Async analysis {job_id} completed")
        
    except Exception as e:
        logger.error(f"Background analysis failed: {e}")
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if job:
            job.status = "failed"
            job.error_message = str(e)
            db.commit()
    finally:
        db.close()


@app.get("/api/v1/jobs/{job_id}", response_model=AnalysisJobResponse)
async def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Get status of an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
    
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    return AnalysisJobResponse(
        job_id=job.job_id,
        status=job.status,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        paths_found=job.total_paths_found or 0,
        paths_pruned=job.paths_pruned or 0,
        error_message=job.error_message
    )


@app.get("/api/v1/jobs/{job_id}/paths")
async def get_job_paths(job_id: str, db: Session = Depends(get_db)):
    """Get attack paths for a completed job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
    
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    paths = db.query(AttackPath).filter(AttackPath.job_id == job.id).all()
    
    return {
        "job_id": job_id,
        "status": job.status,
        "paths": [
            {
                "nodes": p.path_nodes,
                "length": p.path_length,
                "risk_score": p.risk_score,
                "explanation": p.explanation
            }
            for p in paths
        ]
    }


# ============================================================================
# Cloud Integration Endpoints
# ============================================================================

@app.post("/api/v1/cloud/sync-policies")
async def sync_cloud_policies(
    request: CloudPolicyRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Sync policies from cloud provider.
    
    Requires cloud provider credentials configured.
    """
    try:
        # Check if account exists
        account = db.query(ServiceAccount).filter(
            ServiceAccount.name == request.account_name
        ).first()
        
        if not account:
            account = ServiceAccount(
                name=request.account_name,
                provider=request.provider,
                source_type=f"{request.provider}_account"
            )
            db.add(account)
            db.commit()
        
        # Schedule policy sync
        background_tasks.add_task(
            _sync_policies_background,
            account_id=account.id,
            provider=request.provider,
            what=request.what
        )
        
        logger.info(f"Policy sync scheduled for {request.account_name}")
        
        return {
            "account_name": request.account_name,
            "status": "sync_in_progress",
            "message": "Policy sync has been scheduled"
        }
        
    except Exception as e:
        logger.error(f"Policy sync error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _sync_policies_background(account_id: int, provider: str, what: str):
    """Background task for policy synchronization."""
    db = SessionLocal()
    try:
        account = db.query(ServiceAccount).filter(ServiceAccount.id == account_id).first()
        if not account:
            logger.error(f"Account {account_id} not found")
            return
        
        # Parse policies from cloud provider
        policies = parse_cloud_policies(provider, what=what)
        
        # Save to database
        for policy_data in policies:
            policy = Policy(
                name=policy_data.get('PolicyName'),
                policy_type="iam",
                provider=provider,
                principal=policy_data.get('Principal'),
                resource=policy_data.get('Resource'),
                actions=policy_data.get('Action', []),
                conditions=policy_data.get('Condition'),
                account_id=account.id,
                source_arn=policy_data.get('Arn', policy_data.get('id'))
            )
            db.add(policy)
        
        db.commit()
        account.last_sync = datetime.utcnow()
        db.commit()
        
        logger.info(f"Synced {len(policies)} policies for {account.name}")
        
    except Exception as e:
        logger.error(f"Background policy sync failed: {e}")
    finally:
        db.close()


@app.get("/api/v1/policies")
async def list_policies(
    provider: Optional[str] = Query(None),
    policy_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """List policies in database."""
    query = db.query(Policy)
    
    if provider:
        query = query.filter(Policy.provider == provider)
    if policy_type:
        query = query.filter(Policy.policy_type == policy_type)
    
    total = query.count()
    policies = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "type": p.policy_type,
                "provider": p.provider,
                "principal": p.principal,
                "resource": p.resource,
                "actions": p.actions,
                "created_at": p.created_at.isoformat()
            }
            for p in policies
        ]
    }


# ============================================================================
# Phase 3: Formal Verification Endpoints (Z3 SMT Solver)
# ============================================================================

@app.post("/api/v1/verify/path", response_model=VerificationResponse)
async def verify_attack_path(
    request: VerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Formally verify if an attack path is exploitable using Z3 SMT solver.
    
    Returns a mathematical proof that the path is:
    - EXPLOITABLE: Path is provably exploitable under given constraints
    - BLOCKED: Path is provably blocked (no satisfying assignment)
    - UNKNOWN: Cannot determine with current information
    
    Query Parameters:
    - path: List of nodes in the attack path
    - policies: Security policies to check (optional, uses imported if not provided)
    - context: Execution context (source_ip, username, etc.)
    """
    try:
        job_id = str(uuid.uuid4())
        
        # Use provided policies or fetch from database
        policies = request.policies or []
        if not policies:
            # Load policies from database
            db_policies = db.query(Policy).limit(100).all()
            policies = [
                {
                    "effect": "Allow",
                    "conditions": p.conditions or []
                }
                for p in db_policies
            ]
        
        # Run Z3 verification
        verifier = Z3Verifier()
        proof = verifier.verify_path_exploitability(
            request.path,
            policies,
            request.context,
            timeout_ms=5000
        )
        
        logger.info(f"Verification job {job_id}: {proof.result.value} - "
                   f"{proof.explanation[:100]}...")
        
        return VerificationResponse(
            job_id=job_id,
            path=proof.path,
            result=proof.result.value,
            constraints_satisfied=proof.constraints_satisfied,
            num_constraints=proof.num_constraints,
            solver_time_ms=proof.solver_time_ms,
            explanation=proof.explanation,
            created_at=datetime.utcnow().isoformat(),
            constraints_used=proof.constraints_used
        )
    
    except Exception as e:
        logger.error(f"Verification error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Verification failed: {str(e)}"
        )


@app.post("/api/v1/verify/batch")
async def batch_verify_paths(
    request: BatchVerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Formally verify multiple attack paths in batch.
    
    Returns verification results for all paths.
    """
    try:
        job_id = str(uuid.uuid4())
        
        # Use provided policies or fetch from database
        policies = request.policies or []
        if not policies:
            db_policies = db.query(Policy).limit(100).all()
            policies = [
                {
                    "effect": "Allow",
                    "conditions": p.conditions or []
                }
                for p in db_policies
            ]
        
        # Run batch verification
        verifier = Z3Verifier()
        proofs = verifier.batch_verify_paths(
            request.paths,
            policies,
            request.context
        )
        
        results = [
            {
                "path": proof.path,
                "result": proof.result.value,
                "constraints_satisfied": proof.constraints_satisfied,
                "num_constraints": proof.num_constraints,
                "solver_time_ms": proof.solver_time_ms,
                "explanation": proof.explanation
            }
            for proof in proofs
        ]
        
        logger.info(f"Batch verification {job_id}: Verified {len(proofs)} paths")
        
        return {
            "job_id": job_id,
            "total_paths": len(proofs),
            "exploitable_count": sum(1 for p in proofs if p.result == VerificationResult.EXPLOITABLE),
            "blocked_count": sum(1 for p in proofs if p.result == VerificationResult.BLOCKED),
            "results": results,
            "created_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Batch verification error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Batch verification failed: {str(e)}"
        )


@app.get("/api/v1/verify/status")
async def verification_status():
    """
    Get Z3 verification system status and capabilities.
    
    Returns information about the formal verification capabilities.
    """
    return {
        "service": "Z3 SMT Formal Verification",
        "version": "1.0",
        "status": "operational",
        "capabilities": [
            "Attack path exploitability proof",
            "Batch path verification",
            "IAM condition evaluation",
            "Policy constraint satisfaction"
        ],
        "supported_operators": [
            "StringEquals", "StringLike", "StringNotEquals",
            "IpAddress", "NotIpAddress",
            "NumericGreater", "NumericLess", "NumericEquals",
            "ArnLike", "ArnNotLike",
            "Bool"
        ],
        "solver": "Z3 SMT Solver v4.12.2+",
        "max_timeout_ms": 5000
    }


# ============================================================================
# Threat Scoring Endpoints (Phase 3.3)
# ============================================================================

@app.post("/api/v1/threat-score/calculate", response_model=ThreatScoreResponse)
async def calculate_threat_score(request: ThreatScoreRequest):
    """
    Calculate threat score for attack path.
    
    Combines exploitability, impact, path complexity, and Z3 verification
    confidence to produce comprehensive threat assessment.
    
    Args:
        request: Path information and threat factors
    
    Returns:
        Threat score with components and recommendations
    """
    try:
        scorer = PathThreatScorer()
        
        result = scorer.score_path(
            path=request.path,
            is_exploitable=request.is_exploitable,
            cvss_base_score=request.cvss_base_score,
            z3_confidence=request.z3_confidence,
            cve_count=request.cve_count,
            max_cve_score=request.max_cve_score,
            has_authentication_bypass=request.has_authentication_bypass,
            has_privilege_escalation=request.has_privilege_escalation,
        )
        
        # Convert to response model
        components = [
            ThreatComponent(
                name=c.name,
                value=c.value,
                weight=c.weight,
                weighted_value=c.weighted_value,
                description=c.description,
            )
            for c in result.components
        ]
        
        return ThreatScoreResponse(
            path=result.path,
            overall_score=result.overall_score,
            threat_level=result.threat_level.value,
            exploitability_score=result.exploitability_score,
            impact_score=result.impact_score,
            lineage_score=result.lineage_score,
            confidence_score=result.confidence_score,
            cve_count=result.cve_count,
            max_cve_score=result.max_cve_score,
            components=components,
            recommendations=result.recommendations,
        )
    except Exception as e:
        logger.error(f"Threat score calculation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Threat scoring failed: {str(e)}")


@app.post("/api/v1/threat-score/batch", response_model=MultipleThreatScoresResponse)
async def batch_threat_score(request: MultipleThreatScoresRequest):
    """
    Calculate threat scores for multiple paths.
    
    Efficiently scores multiple paths and returns sorted by threat level.
    
    Args:
        request: List of paths to score
    
    Returns:
        Threat scores for all paths, sorted by risk (highest first)
    """
    try:
        scorer = PathThreatScorer()
        results = scorer.score_multiple_paths(request.paths)
        
        # Convert to response models
        threat_responses = []
        threat_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        
        for result in results:
            components = [
                ThreatComponent(
                    name=c.name,
                    value=c.value,
                    weight=c.weight,
                    weighted_value=c.weighted_value,
                    description=c.description,
                )
                for c in result.components
            ]
            
            response = ThreatScoreResponse(
                path=result.path,
                overall_score=result.overall_score,
                threat_level=result.threat_level.value,
                exploitability_score=result.exploitability_score,
                impact_score=result.impact_score,
                lineage_score=result.lineage_score,
                confidence_score=result.confidence_score,
                cve_count=result.cve_count,
                max_cve_score=result.max_cve_score,
                components=components,
                recommendations=result.recommendations,
            )
            threat_responses.append(response)
            
            # Count threat levels
            level = result.threat_level.value
            if level in threat_counts:
                threat_counts[level] += 1
        
        return MultipleThreatScoresResponse(
            scores=threat_responses,
            total_paths=len(results),
            critical_count=threat_counts["Critical"],
            high_count=threat_counts["High"],
            medium_count=threat_counts["Medium"],
            low_count=threat_counts["Low"],
        )
    except Exception as e:
        logger.error(f"Batch threat scoring failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch threat scoring failed: {str(e)}")


@app.post("/api/v1/threat-score/cvss", response_model=CVSSVectorResponse)
async def calculate_cvss_score(request: CVSSVectorRequest):
    """
    Calculate CVSS v3.1 score.
    
    Either provide a CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/...")
    or provide individual metrics.
    
    Args:
        request: CVSS vector or individual metrics
    
    Returns:
        CVSS score and severity
    """
    try:
        calculator = CVSSCalculator()
        
        if request.vector_string:
            # Parse vector string
            score = calculator.calculate_from_vector(request.vector_string)
        else:
            # Use individual metrics
            score = calculator.calculate_base_score(
                attack_vector=request.attack_vector,
                attack_complexity=request.attack_complexity,
                privileges_required=request.privileges_required,
                user_interaction=request.user_interaction,
                scope=request.scope,
                confidentiality=request.confidentiality,
                integrity=request.integrity,
                availability=request.availability,
            )
        
        return CVSSVectorResponse(
            base_score=score.base_score,
            temporal_score=score.temporal_score,
            severity=score.severity,
            vector_string=score.vector_string,
            severity_color=score.severity_color,
        )
    except Exception as e:
        logger.error(f"CVSS calculation failed: {e}")
        raise HTTPException(status_code=500, detail=f"CVSS calculation failed: {str(e)}")


@app.get("/api/v1/threat-score/status")
async def threat_scoring_status():
    """
    Get threat scoring system status and capabilities.
    
    Returns information about the threat assessment capabilities.
    """
    return {
        "service": "Threat Scoring & CVSS Calculator",
        "version": "1.0",
        "status": "operational",
        "capabilities": [
            "CVSS v3.1 scoring",
            "Attack path threat assessment",
            "Multi-factor risk scoring",
            "CVE integration",
            "Batch threat analysis"
        ],
        "weighting_factors": {
            "exploitability": 0.35,
            "impact": 0.35,
            "lineage": 0.20,
            "confidence": 0.10,
        },
        "threat_levels": ["Critical", "High", "Medium", "Low", "Informational"],
        "cvss_version": "3.1"
    }


# ============================================================================
# WebSocket for Real-time Updates
# ============================================================================

@app.websocket("/ws/analysis/{job_id}")
async def websocket_analysis(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint for real-time job updates.
    
    Sends job status and paths as they complete.
    """
    await websocket.accept()
    db = SessionLocal()
    
    try:
        while True:
            job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
            
            if not job:
                await websocket.send_json({"error": "Job not found"})
                break
            
            # Send current status
            await websocket.send_json({
                "job_id": job_id,
                "status": job.status,
                "paths_found": job.total_paths_found or 0,
                "paths_pruned": job.paths_pruned or 0
            })
            
            # If completed, send paths and close
            if job.status in ["completed", "failed"]:
                if job.status == "completed":
                    paths = db.query(AttackPath).filter(AttackPath.job_id == job.id).all()
                    for path in paths:
                        await websocket.send_json({
                            "type": "path",
                            "nodes": path.path_nodes,
                            "risk_score": path.risk_score,
                            "explanation": path.explanation
                        })
                
                await websocket.send_json({"status": "done"})
                break
            
            # Wait before checking again
            await asyncio.sleep(1)
            
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        db.close()


# ============================================================================
# Initialization
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    try:
        init_db()
        logger.info("Database initialized")
        
        # Pre-load graph
        get_cached_graph()
        logger.info("Security graph loaded")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")


if __name__ == "__main__":
    import uvicorn
    
    logging.basicConfig(level=logging.INFO)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
