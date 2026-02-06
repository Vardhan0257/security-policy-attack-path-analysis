import re
import ipaddress
from typing import Any, Dict, List, Union


class ConditionEvaluator:
    """
    Evaluates whether an IAM policy condition is satisfied
    under a given execution context with support for multiple operators.
    
    Supports operators: StringEquals, StringNotEquals, StringLike, 
    IpAddress, NotIpAddress, NumericGreaterThan, NumericLessThan,
    NumericGreaterThanEquals, NumericLessThanEquals, DateGreaterThan,
    StringEqualsIgnoreCase, ArnLike, and list operators.
    """

    def __init__(self, context: Dict[str, Any]):
        """
        Args:
            context: dict describing current execution environment
            Example:
                {
                    "source_ip": "192.168.1.1",
                    "time_of_day": "business_hours",
                    "user_agent": "Chrome"
                }
        """
        self.context = context or {}

    def is_satisfied(self, condition: Union[Dict, None]) -> bool:
        """
        Evaluate if condition dict is satisfied under current context.
        
        Args:
            condition: dict from IAM policy or None
            
        Returns:
            True if ALL conditions hold, else False
        """
        if not condition:
            return True
        
        if not isinstance(condition, dict):
            return False

        # Each key in condition dict must be satisfied
        for key, value in condition.items():
            if not self._evaluate_condition_key(key, value):
                return False

        return True

    def _evaluate_condition_key(self, key: str, value: Any) -> bool:
        """Evaluate a single condition key-value pair."""
        try:
            # Parse operator and context key: e.g., "StringEquals:source_ip"
            parts = key.split(":")
            if len(parts) == 2:
                operator, context_key = parts
            elif len(parts) == 1:
                # Default to StringEquals if no operator specified
                operator = "StringEquals"
                context_key = parts[0]
            else:
                return False

            context_value = self.context.get(context_key)
            return self._apply_operator(operator, context_value, value)
        except Exception:
            return False

    def _apply_operator(self, operator: str, context_val: Any, policy_val: Any) -> bool:
        """Apply specific operator logic."""
        
        if operator == "StringEquals":
            return self._string_equals(context_val, policy_val)
        elif operator == "StringNotEquals":
            return not self._string_equals(context_val, policy_val)
        elif operator == "StringEqualsIgnoreCase":
            return self._string_equals_ignore_case(context_val, policy_val)
        elif operator == "StringLike":
            return self._string_like(context_val, policy_val)
        elif operator == "StringNotLike":
            return not self._string_like(context_val, policy_val)
        elif operator == "IpAddress":
            return self._ip_address_match(context_val, policy_val)
        elif operator == "NotIpAddress":
            return not self._ip_address_match(context_val, policy_val)
        elif operator == "NumericEquals":
            return self._numeric_equals(context_val, policy_val)
        elif operator == "NumericNotEquals":
            return not self._numeric_equals(context_val, policy_val)
        elif operator == "NumericGreaterThan":
            return self._numeric_greater_than(context_val, policy_val)
        elif operator == "NumericGreaterThanEquals":
            return self._numeric_greater_than(context_val, policy_val, equals=True)
        elif operator == "NumericLessThan":
            return self._numeric_less_than(context_val, policy_val)
        elif operator == "NumericLessThanEquals":
            return self._numeric_less_than(context_val, policy_val, equals=True)
        elif operator == "NumericDateGreaterThan":
            return self._date_greater_than(context_val, policy_val)
        elif operator == "NumericDateLessThan":
            return self._date_less_than(context_val, policy_val)
        elif operator == "ArnLike":
            return self._arn_like(context_val, policy_val)
        elif operator == "ArnNotLike":
            return not self._arn_like(context_val, policy_val)
        elif operator == "Bool":
            return self._bool_equals(context_val, policy_val)
        else:
            # Unknown operator defaults to False
            return False

    @staticmethod
    def _string_equals(context_val: Any, policy_val: Any) -> bool:
        """Check exact string equality."""
        if context_val is None:
            return False
        if isinstance(policy_val, list):
            return str(context_val) in [str(v) for v in policy_val]
        return str(context_val) == str(policy_val)

    @staticmethod
    def _string_equals_ignore_case(context_val: Any, policy_val: Any) -> bool:
        """Check case-insensitive string equality."""
        if context_val is None:
            return False
        if isinstance(policy_val, list):
            context_lower = str(context_val).lower()
            return context_lower in [str(v).lower() for v in policy_val]
        return str(context_val).lower() == str(policy_val).lower()

    @staticmethod
    def _string_like(context_val: Any, policy_val: Any) -> bool:
        """Check string pattern match using wildcards (* and ?)."""
        if context_val is None:
            return False
        
        values = policy_val if isinstance(policy_val, list) else [policy_val]
        context_str = str(context_val)
        
        for val in values:
            # Convert IAM wildcard pattern to regex
            pattern = str(val).replace(".", r"\.").replace("*", ".*").replace("?", ".")
            if re.match(f"^{pattern}$", context_str):
                return True
        return False

    @staticmethod
    def _ip_address_match(context_val: Any, policy_val: Any) -> bool:
        """Check IP address match (supports CIDR notation)."""
        if context_val is None:
            return False
        
        try:
            context_ip = ipaddress.ip_address(str(context_val))
            values = policy_val if isinstance(policy_val, list) else [policy_val]
            
            for val in values:
                try:
                    # Try as CIDR range first
                    if "/" in str(val):
                        network = ipaddress.ip_network(str(val), strict=False)
                        if context_ip in network:
                            return True
                    else:
                        # Try as individual IP
                        policy_ip = ipaddress.ip_address(str(val))
                        if context_ip == policy_ip:
                            return True
                except ValueError:
                    continue
            return False
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _numeric_equals(context_val: Any, policy_val: Any) -> bool:
        """Check numeric equality."""
        try:
            context_num = float(context_val)
            if isinstance(policy_val, list):
                return context_num in [float(v) for v in policy_val]
            return context_num == float(policy_val)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _numeric_greater_than(context_val: Any, policy_val: Any, equals: bool = False) -> bool:
        """Check if context value is greater than policy value."""
        try:
            context_num = float(context_val)
            policy_num = float(policy_val)
            if equals:
                return context_num >= policy_num
            return context_num > policy_num
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _numeric_less_than(context_val: Any, policy_val: Any, equals: bool = False) -> bool:
        """Check if context value is less than policy value."""
        try:
            context_num = float(context_val)
            policy_num = float(policy_val)
            if equals:
                return context_num <= policy_num
            return context_num < policy_num
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _date_greater_than(context_val: Any, policy_val: Any) -> bool:
        """Check date comparison (ISO 8601 format)."""
        try:
            return str(context_val) > str(policy_val)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _date_less_than(context_val: Any, policy_val: Any) -> bool:
        """Check date comparison (ISO 8601 format)."""
        try:
            return str(context_val) < str(policy_val)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _arn_like(context_val: Any, policy_val: Any) -> bool:
        """Check ARN pattern match (AWS Resource Name)."""
        if context_val is None:
            return False
        context_str = str(context_val)
        values = policy_val if isinstance(policy_val, list) else [policy_val]
        
        for val in values:
            pattern = str(val).replace("*", ".*").replace("?", ".")
            if re.match(f"^{pattern}$", context_str):
                return True
        return False

    @staticmethod
    def _bool_equals(context_val: Any, policy_val: Any) -> bool:
        """Check boolean equality."""
        try:
            context_bool = str(context_val).lower() in ("true", "1", "yes")
            policy_bool = str(policy_val).lower() in ("true", "1", "yes")
            return context_bool == policy_bool
        except (ValueError, TypeError):
            return False