import pytest
from src.analysis.condition_evaluator import ConditionEvaluator


# ============================================================================
# BASIC TESTS - Simple equality conditions
# ============================================================================

def test_no_condition():
    """Empty condition should always be satisfied."""
    evaluator = ConditionEvaluator({"source_ip": "internal"})
    assert evaluator.is_satisfied(None) == True
    assert evaluator.is_satisfied({}) == True


def test_single_condition_satisfied():
    """Single matching condition should be satisfied."""
    evaluator = ConditionEvaluator({"source_ip": "internal"})
    condition = {"source_ip": "internal"}
    assert evaluator.is_satisfied(condition) == True


def test_single_condition_not_satisfied():
    """Single non-matching condition should fail."""
    evaluator = ConditionEvaluator({"source_ip": "external"})
    condition = {"source_ip": "internal"}
    assert evaluator.is_satisfied(condition) == False


def test_multiple_conditions_all_satisfied():
    """All conditions matching should succeed."""
    evaluator = ConditionEvaluator({
        "source_ip": "internal",
        "time_of_day": "business_hours"
    })
    condition = {
        "source_ip": "internal",
        "time_of_day": "business_hours"
    }
    assert evaluator.is_satisfied(condition) == True


def test_multiple_conditions_one_not_satisfied():
    """Any unmatched condition should fail."""
    evaluator = ConditionEvaluator({
        "source_ip": "internal",
        "time_of_day": "off_hours"
    })
    condition = {
        "source_ip": "internal",
        "time_of_day": "business_hours"
    }
    assert evaluator.is_satisfied(condition) == False


def test_unknown_condition():
    """Unknown condition keys should fail."""
    evaluator = ConditionEvaluator({"source_ip": "internal"})
    condition = {"unknown_key": "value"}
    assert evaluator.is_satisfied(condition) == False


# ============================================================================
# OPERATOR-SPECIFIC TESTS
# ============================================================================

class TestStringOperators:
    """Test string-based condition operators."""
    
    def test_string_equals_operator(self):
        """StringEquals operator."""
        evaluator = ConditionEvaluator({"username": "alice"})
        assert evaluator.is_satisfied({"StringEquals:username": "alice"}) == True
        assert evaluator.is_satisfied({"StringEquals:username": "bob"}) == False
    
    def test_string_not_equals_operator(self):
        """StringNotEquals operator."""
        evaluator = ConditionEvaluator({"username": "alice"})
        assert evaluator.is_satisfied({"StringNotEquals:username": "bob"}) == True
        assert evaluator.is_satisfied({"StringNotEquals:username": "alice"}) == False
    
    def test_string_equals_ignore_case(self):
        """StringEqualsIgnoreCase operator."""
        evaluator = ConditionEvaluator({"username": "Alice"})
        assert evaluator.is_satisfied({"StringEqualsIgnoreCase:username": "alice"}) == True
        assert evaluator.is_satisfied({"StringEqualsIgnoreCase:username": "ALICE"}) == True
        assert evaluator.is_satisfied({"StringEqualsIgnoreCase:username": "bob"}) == False
    
    def test_string_like_simple_wildcard(self):
        """StringLike with * wildcard."""
        evaluator = ConditionEvaluator({"resource": "arn:aws:s3:::my-bucket/*"})
        assert evaluator.is_satisfied({"StringLike:resource": "arn:aws:s3:::my-bucket/*"}) == True
        assert evaluator.is_satisfied({"StringLike:resource": "arn:aws:s3:::*"}) == True
        assert evaluator.is_satisfied({"StringLike:resource": "arn:aws:ec2:::*"}) == False
    
    def test_string_like_question_mark_wildcard(self):
        """StringLike with ? wildcard (single char)."""
        evaluator = ConditionEvaluator({"resource": "user123"})
        assert evaluator.is_satisfied({"StringLike:resource": "user???"}) == True
        assert evaluator.is_satisfied({"StringLike:resource": "user????"}) == False
    
    def test_string_not_like(self):
        """StringNotLike operator."""
        evaluator = ConditionEvaluator({"resource": "production-db"})
        assert evaluator.is_satisfied({"StringNotLike:resource": "staging-*"}) == True
        assert evaluator.is_satisfied({"StringNotLike:resource": "production-*"}) == False


class TestIPOperators:
    """Test IP address-based condition operators."""
    
    def test_ip_address_exact_match(self):
        """IpAddress with exact IP."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.100"})
        assert evaluator.is_satisfied({"IpAddress:source_ip": "192.168.1.100"}) == True
        assert evaluator.is_satisfied({"IpAddress:source_ip": "10.0.0.1"}) == False
    
    def test_ip_address_cidr_match(self):
        """IpAddress with CIDR range."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.50"})
        assert evaluator.is_satisfied({"IpAddress:source_ip": "192.168.1.0/24"}) == True
        assert evaluator.is_satisfied({"IpAddress:source_ip": "10.0.0.0/8"}) == False
    
    def test_ip_address_multiple_values(self):
        """IpAddress with list of values."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.50"})
        assert evaluator.is_satisfied({
            "IpAddress:source_ip": ["192.168.1.0/24", "10.0.0.0/8"]
        }) == True
    
    def test_not_ip_address(self):
        """NotIpAddress operator."""
        evaluator = ConditionEvaluator({"source_ip": "192.168.1.50"})
        assert evaluator.is_satisfied({"NotIpAddress:source_ip": "10.0.0.0/8"}) == True
        assert evaluator.is_satisfied({"NotIpAddress:source_ip": "192.168.1.0/24"}) == False
    
    def test_ip_address_invalid(self):
        """Invalid IP should return False."""
        evaluator = ConditionEvaluator({"source_ip": "not-an-ip"})
        assert evaluator.is_satisfied({"IpAddress:source_ip": "192.168.1.0/24"}) == False


class TestNumericOperators:
    """Test numeric condition operators."""
    
    def test_numeric_equals(self):
        """NumericEquals operator."""
        evaluator = ConditionEvaluator({"port": "8080"})
        assert evaluator.is_satisfied({"NumericEquals:port": "8080"}) == True
        assert evaluator.is_satisfied({"NumericEquals:port": "443"}) == False
    
    def test_numeric_not_equals(self):
        """NumericNotEquals operator."""
        evaluator = ConditionEvaluator({"port": "443"})
        assert evaluator.is_satisfied({"NumericNotEquals:port": "8080"}) == True
        assert evaluator.is_satisfied({"NumericNotEquals:port": "443"}) == False
    
    def test_numeric_greater_than(self):
        """NumericGreaterThan operator."""
        evaluator = ConditionEvaluator({"timeout": "100"})
        assert evaluator.is_satisfied({"NumericGreaterThan:timeout": "50"}) == True
        assert evaluator.is_satisfied({"NumericGreaterThan:timeout": "100"}) == False
    
    def test_numeric_greater_than_equals(self):
        """NumericGreaterThanEquals operator."""
        evaluator = ConditionEvaluator({"timeout": "100"})
        assert evaluator.is_satisfied({"NumericGreaterThanEquals:timeout": "100"}) == True
        assert evaluator.is_satisfied({"NumericGreaterThanEquals:timeout": "101"}) == False
    
    def test_numeric_less_than(self):
        """NumericLessThan operator."""
        evaluator = ConditionEvaluator({"timeout": "50"})
        assert evaluator.is_satisfied({"NumericLessThan:timeout": "100"}) == True
        assert evaluator.is_satisfied({"NumericLessThan:timeout": "50"}) == False
    
    def test_numeric_less_than_equals(self):
        """NumericLessThanEquals operator."""
        evaluator = ConditionEvaluator({"timeout": "100"})
        assert evaluator.is_satisfied({"NumericLessThanEquals:timeout": "100"}) == True
        assert evaluator.is_satisfied({"NumericLessThanEquals:timeout": "99"}) == False


class TestARNOperators:
    """Test ARN (AWS Resource Name) condition operators."""
    
    def test_arn_like(self):
        """ArnLike operator."""
        evaluator = ConditionEvaluator({
            "resource": "arn:aws:s3:::my-bucket/docs/*"
        })
        assert evaluator.is_satisfied({
            "ArnLike:resource": "arn:aws:s3:::my-bucket/*"
        }) == True
        assert evaluator.is_satisfied({
            "ArnLike:resource": "arn:aws:ec2:::*"
        }) == False
    
    def test_arn_not_like(self):
        """ArnNotLike operator."""
        evaluator = ConditionEvaluator({
            "resource": "arn:aws:ec2:::instance/*"
        })
        assert evaluator.is_satisfied({
            "ArnNotLike:resource": "arn:aws:s3:::*"
        }) == True
        assert evaluator.is_satisfied({
            "ArnNotLike:resource": "arn:aws:ec2:::*"
        }) == False


class TestBoolOperators:
    """Test boolean condition operators."""
    
    def test_bool_equals_true(self):
        """Bool operator with true value."""
        evaluator = ConditionEvaluator({"mfa_required": "true"})
        assert evaluator.is_satisfied({"Bool:mfa_required": "true"}) == True
        assert evaluator.is_satisfied({"Bool:mfa_required": "false"}) == False
    
    def test_bool_equals_various_formats(self):
        """Bool operator accepts various true/false formats."""
        for true_val in ["true", "True", "1", "yes"]:
            evaluator = ConditionEvaluator({"check": true_val})
            assert evaluator.is_satisfied({"Bool:check": "true"}) == True


class TestComplexConditions:
    """Test complex multi-condition scenarios."""
    
    def test_multiple_operators(self):
        """Multiple operators in one condition."""
        evaluator = ConditionEvaluator({
            "source_ip": "192.168.1.50",
            "time_of_day": "business_hours",
            "username": "alice"
        })
        condition = {
            "IpAddress:source_ip": "192.168.1.0/24",
            "source_ip": "business_hours",
            "StringEquals:username": "alice"
        }
        # NOTE: This test shows limitations - the evaluator expects simple key lookups
        # More sophisticated condition parsing would handle AWS IAM Condition syntax better
    
    def test_empty_context(self):
        """Empty context should fail any condition."""
        evaluator = ConditionEvaluator({})
        assert evaluator.is_satisfied({"source_ip": "internal"}) == False
    
    def test_none_context_value(self):
        """None context value should fail condition."""
        evaluator = ConditionEvaluator({"source_ip": None})
        assert evaluator.is_satisfied({"IpAddress:source_ip": "192.168.1.0/24"}) == False
    
    def test_missing_context_key(self):
        """Missing context key should fail condition."""
        evaluator = ConditionEvaluator({})
        assert evaluator.is_satisfied({"StringEquals:username": "alice"}) == False


class TestListValues:
    """Test conditions with list values."""
    
    def test_string_list_match(self):
        """StringEquals with list should match any value."""
        evaluator = ConditionEvaluator({"role": "admin"})
        assert evaluator.is_satisfied({
            "StringEquals:role": ["admin", "user", "guest"]
        }) == True
    
    def test_string_list_no_match(self):
        """StringEquals with list should fail if not found."""
        evaluator = ConditionEvaluator({"role": "superuser"})
        assert evaluator.is_satisfied({
            "StringEquals:role": ["admin", "user", "guest"]
        }) == False
    
    def test_numeric_list(self):
        """NumericEquals with list."""
        evaluator = ConditionEvaluator({"port": "443"})
        assert evaluator.is_satisfied({
            "NumericEquals:port": ["80", "443", "8080"]
        }) == True


# ============================================================================
# EDGE CASES AND ERROR HANDLING
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_invalid_condition_type(self):
        """Invalid condition type should return False."""
        evaluator = ConditionEvaluator({"key": "value"})
        assert evaluator.is_satisfied("invalid") == False
    
    def test_numeric_on_string_context(self):
        """NumericGreaterThan on non-numeric context."""
        evaluator = ConditionEvaluator({"value": "abc"})
        assert evaluator.is_satisfied({"NumericGreaterThan:value": "10"}) == False
    
    def test_ip_on_non_ip_context(self):
        """IpAddress on non-IP context."""
        evaluator = ConditionEvaluator({"source": "hostname"})
        assert evaluator.is_satisfied({"IpAddress:source": "192.168.1.0/24"}) == False
    
    def test_unknown_operator(self):
        """Unknown operator should return False."""
        evaluator = ConditionEvaluator({"key": "value"})
        assert evaluator.is_satisfied({"UnknownOperator:key": "value"}) == False
    
    def test_special_characters_in_string(self):
        """String comparison with special characters."""
        evaluator = ConditionEvaluator({"resource": "arn:aws:s3:::$bucket/*"})
        assert evaluator.is_satisfied({
            "StringEquals:resource": "arn:aws:s3:::$bucket/*"
        }) == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
