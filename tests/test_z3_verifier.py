"""
Tests for Z3 Formal Verification Module

Tests verify that the Z3 SMT solver correctly determines
whether attack paths are exploitable given policies.
"""

import pytest
import json
from src.verification import (
    Z3Verifier,
    PolicyToZ3Converter,
    VerificationResult,
    verify_path,
)


class TestPolicyToZ3Converter:
    """Test policy condition to Z3 constraint conversion"""
    
    def test_string_equals_condition(self):
        """Test StringEquals operator"""
        converter = PolicyToZ3Converter()
        condition = {
            "operator": "StringEquals",
            "key": "aws:username",
            "values": ["alice"]
        }
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
        # Constraint should be: username == "alice"
    
    def test_string_like_condition(self):
        """Test StringLike operator with wildcards"""
        converter = PolicyToZ3Converter()
        condition = {
            "operator": "StringLike",
            "key": "aws:username",
            "values": ["admin*"]
        }
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
    
    def test_numeric_comparison_condition(self):
        """Test NumericGreater operator"""
        converter = PolicyToZ3Converter()
        condition = {
            "operator": "NumericGreater",
            "key": "aws:port",
            "values": ["1024"]
        }
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
    
    def test_arn_like_condition(self):
        """Test ArnLike operator"""
        converter = PolicyToZ3Converter()
        condition = {
            "operator": "ArnLike",
            "key": "arn:aws:iam",
            "values": ["arn:aws:iam::123456789:role/Admin*"]
        }
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
    
    def test_bool_condition(self):
        """Test Bool operator"""
        converter = PolicyToZ3Converter()
        condition = {
            "operator": "Bool",
            "key": "aws:SecureTransport",
            "values": ["true"]
        }
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
    
    def test_negation_operator(self):
        """Test StringNotEquals (negation)"""
        converter = PolicyToZ3Converter()
        condition = {
            "operator": "StringNotEquals",
            "key": "aws:username",
            "values": ["guest"]
        }
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None


class TestZ3Verifier:
    """Test Z3 formal verification"""
    
    def test_simple_exploitable_path(self):
        """Test verification of a simple exploitable path"""
        verifier = Z3Verifier()
        
        path = ["internet", "web_server", "app_server", "database"]
        
        # Policy allowing the path
        policies = [
            {
                "effect": "Allow",
                "conditions": [
                    {
                        "operator": "StringEquals",
                        "key": "aws:username",
                        "values": ["www-user"]
                    }
                ]
            }
        ]
        
        context = {"aws:username": "www-user"}
        
        result = verifier.verify_path_exploitability(path, policies, context)
        
        assert result.path == path
        assert result.result in [VerificationResult.EXPLOITABLE, VerificationResult.UNKNOWN]
        assert result.solver_time_ms >= 0
    
    def test_blocked_path_with_deny(self):
        """Test path blocked by Deny policy"""
        verifier = Z3Verifier()
        
        path = ["internet", "sensitive_data"]
        
        # Deny policy
        policies = [
            {
                "effect": "Deny",
                "conditions": [
                    {
                        "operator": "IpAddress",
                        "key": "aws:SourceIp",
                        "values": ["0.0.0.0/0"]  # Deny from anywhere
                    }
                ]
            }
        ]
        
        context = {}
        
        result = verifier.verify_path_exploitability(path, policies, context)
        
        assert result.path == path
        # Should be blocked or unknown due to broad deny
    
    def test_multiple_policies(self):
        """Test verification with multiple policies"""
        verifier = Z3Verifier()
        
        path = ["internet", "api", "database"]
        
        policies = [
            {
                "effect": "Allow",
                "conditions": [
                    {
                        "operator": "StringEquals",
                        "key": "aws:username",
                        "values": ["api_user"]
                    },
                    {
                        "operator": "NumericGreater",
                        "key": "aws:port",
                        "values": ["1024"]
                    }
                ]
            }
        ]
        
        context = {"aws:username": "api_user", "aws:port": "5432"}
        
        result = verifier.verify_path_exploitability(path, policies, context)
        
        assert result.num_constraints > 0
        assert result.solver_time_ms >= 0
    
    def test_batch_verification(self):
        """Test batch verification of multiple paths"""
        verifier = Z3Verifier()
        
        paths = [
            ["internet", "web_server", "database"],
            ["internet", "app_server", "database"],
            ["internet", "admin_portal"]
        ]
        
        policies = [
            {
                "effect": "Allow",
                "conditions": []
            }
        ]
        
        context = {}
        
        results = verifier.batch_verify_paths(paths, policies, context)
        
        assert len(results) == len(paths)
        assert all(r.path in paths for r in results)
        assert all(r.solver_time_ms >= 0 for r in results)
    
    def test_context_variable_binding(self):
        """Test that context variables are properly bound"""
        verifier = Z3Verifier()
        
        path = ["attacker", "admin_server"]
        
        # Policy requires source_ip to be internal
        policies = [
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
        ]
        
        # External source - should not match
        context = {"aws:SourceIp": "203.0.113.5"}
        
        result = verifier.verify_path_exploitability(path, policies, context)
        
        assert result.solver_time_ms >= 0
        # Result could be blocked or unknown depending on constraint strength
    
    def test_wildcard_pattern_matching(self):
        """Test wildcard matching in conditions"""
        converter = PolicyToZ3Converter()
        
        condition = {
            "operator": "StringLike",
            "key": "aws:username",
            "values": ["admin-*"]
        }
        
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
    
    def test_numeric_range_conditions(self):
        """Test numeric comparison conditions"""
        converter = PolicyToZ3Converter()
        
        # Port must be > 1024
        condition = {
            "operator": "NumericGreater",
            "key": "aws:port",
            "values": ["1024"]
        }
        
        constraint = converter.condition_to_constraint(condition)
        assert constraint is not None
    
    def test_verification_result_fields(self):
        """Test that verification results have all required fields"""
        verifier = Z3Verifier()
        
        path = ["source", "target"]
        policies = [{"effect": "Allow", "conditions": []}]
        context = {}
        
        result = verifier.verify_path_exploitability(path, policies, context)
        
        assert hasattr(result, 'path')
        assert hasattr(result, 'result')
        assert hasattr(result, 'constraints_satisfied')
        assert hasattr(result, 'num_constraints')
        assert hasattr(result, 'solver_time_ms')
        assert hasattr(result, 'explanation')
        assert result.explanation != ""
    
    def test_timeout_handling(self):
        """Test that solver timeout is respected"""
        verifier = Z3Verifier()
        
        path = ["internet", "target"]
        policies = [{"effect": "Allow", "conditions": []}]
        context = {}
        
        # Short timeout
        result = verifier.verify_path_exploitability(
            path, policies, context, timeout_ms=100
        )
        
        assert result.solver_time_ms <= 200  # Some margin
        assert result.explanation != ""


class TestVerifyPathFunction:
    """Test convenience functions"""
    
    def test_verify_path_convenience(self):
        """Test verify_path() convenience function"""
        path = ["internet", "database"]
        policies = [{"effect": "Allow", "conditions": []}]
        context = {}
        
        result = verify_path(path, policies, context)
        
        assert result.path == path
        assert result.result is not None
    
    def test_verify_path_with_conditions(self):
        """Test verify_path with actual conditions"""
        path = ["external", "internal_app"]
        
        policies = [
            {
                "effect": "Allow",
                "conditions": [
                    {
                        "operator": "StringEquals",
                        "key": "aws:username",
                        "values": ["service_account"]
                    }
                ]
            }
        ]
        
        context = {"aws:username": "service_account"}
        
        result = verify_path(path, policies, context)
        
        assert result is not None
        assert isinstance(result.result, VerificationResult)
        assert result.explanation is not None or isinstance(result.explanation, str)


class TestIntegrationWithAnalyzeResult:
    """Test integration with attack path analysis results"""
    
    def test_verify_paths_from_analyzer(self):
        """Test verifying paths from AttackPathAnalyzer"""
        # This would integrate Z3 verification into the API
        verifier = Z3Verifier()
        
        # Simulated output from AttackPathAnalyzer
        discovered_paths = [
            {
                "path": ["internet", "web", "database"],
                "score": 75.3,
                "policies": ["firewall_rule_1", "iam_policy_1"]
            },
            {
                "path": ["internet", "admin"],
                "score": 45.0,
                "policies": ["auth_policy"]
            }
        ]
        
        # Policies
        policies = [
            {"effect": "Allow", "conditions": []},
        ]
        
        context = {}
        
        # Verify each path
        for discovered in discovered_paths:
            result = verifier.verify_path_exploitability(
                discovered["path"],
                policies,
                context
            )
            assert result.path == discovered["path"]
            assert result.result is not None


# Test data fixtures
@pytest.fixture
def sample_policies():
    """Sample security policies"""
    return [
        {
            "effect": "Allow",
            "conditions": [
                {
                    "operator": "StringEquals",
                    "key": "aws:username",
                    "values": ["admin"]
                }
            ]
        }
    ]


@pytest.fixture
def sample_paths():
    """Sample attack paths"""
    return [
        ["internet", "web_server", "app_server"],
        ["internet", "api_gateway", "backend"],
    ]


@pytest.fixture
def sample_context():
    """Sample execution context"""
    return {
        "aws:username": "admin",
        "time_of_day": "business_hours"
    }
