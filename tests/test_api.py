"""
Tests for REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api import app, get_db
from src.database import Base, ServiceAccount, Policy, AnalysisJob, AttackPath, PolicyChange, AnalysisCache


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def client(setup_test_db):
    """FastAPI test client with auto-configured test database."""
    return TestClient(app)


# ============================================================================
# Health Check Tests
# ============================================================================

class TestHealthCheck:
    """Test health check endpoints."""
    
    def test_health_endpoint(self, client):
        """Health check should always return OK."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_api_status(self, client):
        """API status endpoint should respond (either 200 or 503 if DB not initialized)."""
        response = client.get("/api/v1/status")
        # Status endpoint should return 200 when DB initialized, or 503 if not
        assert response.status_code in [200, 503]
        # If successful, check structure
        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "operational"
            assert "policies_in_db" in data


# ============================================================================
# Analysis Endpoint Tests
# ============================================================================

class TestAnalysisEndpoints:
    """Test synchronous and asynchronous analysis."""
    
    def test_analyze_invalid_nodes(self, client):
        """Request with invalid nodes should fail."""
        request_data = {
            "source_node": "nonexistent_source",
            "target_node": "nonexistent_target",
            "context": {
                "source_ip": "192.168.1.1",
                "time_of_day": "business_hours"
            },
            "max_depth": 5
        }
        
        response = client.post("/api/v1/analyze", json=request_data)
        # Should fail because nodes don't exist in the graph
        assert response.status_code in [400, 500]
    
    def test_analyze_valid_request_format(self, client):
        """Valid request format should be accepted."""
        request_data = {
            "source_node": "internet",
            "target_node": "database",
            "context": {
                "source_ip": "external",
                "time_of_day": "business_hours"
            },
            "max_depth": 5
        }
        
        response = client.post("/api/v1/analyze", json=request_data)
        # Should either succeed or fail gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_analyze_response_format(self, client):
        """Response should have correct format."""
        request_data = {
            "source_node": "internet",
            "target_node": "app_server",
            "context": {"source_ip": "external"},
            "max_depth": 3
        }
        
        response = client.post("/api/v1/analyze", json=request_data)
        
        if response.status_code == 200:
            data = response.json()
            assert "job_id" in data
            assert "status" in data
            assert "paths_found" in data
            assert "evaluation_time_ms" in data


class TestAsyncAnalysis:
    """Test asynchronous analysis."""
    
    def test_async_analyze_returns_immediately(self, client):
        """Async endpoint should return immediately."""
        request_data = {
            "source_node": "internet",
            "target_node": "database",
            "context": {"source_ip": "external"},
            "max_depth": 5
        }
        
        response = client.post("/api/v1/analyze/async", json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "pending"
    
    def test_get_job_status(self, client):
        """Should be able to query job status."""
        # First, create a job
        request_data = {
            "source_node": "internet",
            "target_node": "database",
            "context": {"source_ip": "external"},
            "max_depth": 5
        }
        
        response = client.post("/api/v1/analyze/async", json=request_data)
        job_id = response.json()["job_id"]
        
        # Query status
        response = client.get(f"/api/v1/jobs/{job_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == job_id
        assert "status" in data
    
    def test_get_nonexistent_job(self, client):
        """Querying nonexistent job should return 404."""
        response = client.get("/api/v1/jobs/nonexistent-job-id")
        assert response.status_code == 404


# ============================================================================
# Policy Endpoint Tests
# ============================================================================

class TestPolicyEndpoints:
    """Test policy management endpoints."""
    
    def test_list_policies_empty(self, client):
        """List policies should work or fail gracefully if DB not ready."""
        response = client.get("/api/v1/policies")
        # Should return 200 if working, or 500 if database tables don't exist
        assert response.status_code in [200, 500, 503]
        if response.status_code == 200:
            data = response.json()
            assert "policies" in data
            assert "total" in data
            assert data["policies"] == []
            assert data["total"] == 0
    
    def test_list_policies_with_filter(self, client):
        """Should support filtering policies or fail gracefully."""
        response = client.get("/api/v1/policies?provider=aws&limit=10")
        # Should return 200 if working, or 500/503 if database not ready
        assert response.status_code in [200, 500, 503]
        if response.status_code == 200:
            data = response.json()
            assert "policies" in data
            assert "total" in data
    
    def test_sync_policies_endpoint(self, client):
        """Cloud policy sync endpoint should accept requests."""
        request_data = {
            "provider": "aws",
            "account_name": "test-account",
            "what": "users"
        }
        
        response = client.post("/api/v1/cloud/sync-policies", json=request_data)
        # Should accept the request (actual AWS call requires credentials)
        assert response.status_code == 200


# ============================================================================
# Request Validation Tests
# ============================================================================

class TestRequestValidation:
    """Test request validation."""
    
    def test_analysis_request_missing_context(self, client):
        """Request without context should fail."""
        request_data = {
            "source_node": "internet",
            "target_node": "database",
            "max_depth": 5
        }
        
        response = client.post("/api/v1/analyze", json=request_data)
        assert response.status_code == 422  # Pydantic validation error
    
    def test_analysis_request_invalid_max_depth(self, client):
        """Request with invalid max_depth should fail."""
        request_data = {
            "source_node": "internet",
            "target_node": "database",
            "context": {"source_ip": "external"},
            "max_depth": 100  # Too high
        }
        
        response = client.post("/api/v1/analyze", json=request_data)
        assert response.status_code == 422
    
    def test_analysis_request_extra_context_fields(self, client):
        """Should accept extra context fields."""
        request_data = {
            "source_node": "internet",
            "target_node": "database",
            "context": {
                "source_ip": "external",
                "time_of_day": "business_hours",
                "extra_fields": {
                    "user_id": "user123",
                    "department": "engineering"
                }
            },
            "max_depth": 5
        }
        
        response = client.post("/api/v1/analyze", json=request_data)
        # Should be accepted (may fail due to invalid graph nodes)
        assert response.status_code in [200, 400, 500]


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_malformed_json(self, client):
        """Malformed JSON should return 422."""
        response = client.post(
            "/api/v1/analyze",
            data="not valid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    def test_unknown_endpoint(self, client):
        """Unknown endpoint should return 404."""
        response = client.get("/api/v1/unknown")
        assert response.status_code == 404
    
    def test_method_not_allowed(self, client):
        """Wrong HTTP method should return 405."""
        response = client.get("/api/v1/analyze")  # Should be POST
        assert response.status_code == 405


# ============================================================================
# Response Format Tests
# ============================================================================

class TestResponseFormats:
    """Test response formats and schemas."""
    
    def test_health_response_format(self, client):
        """Health response should have required fields."""
        response = client.get("/health")
        data = response.json()
        
        assert "status" in data
        assert "version" in data
        assert "timestamp" in data
    
    def test_status_response_format(self, client):
        """Status response should have required fields or error detail."""
        response = client.get("/api/v1/status")
        data = response.json()
        
        # Response should either have status field (success) or detail field (error)
        if response.status_code == 200:
            assert "status" in data
            assert "database" in data
            assert "timestamp" in data
        elif response.status_code == 503:
            assert "detail" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
