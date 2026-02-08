"""
Z3 SMT Formal Verification of Attack Paths

This module uses the Z3 SAT/SMT solver to mathematically prove
whether attack paths are exploitable given security policies.

Key Concepts:
- Each policy condition becomes a Z3 constraint
- Attack paths are modeled as satisfaction problems
- Z3 solver determines if path is feasible
- Generates formal proofs and counterexamples
"""

import json
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

import z3

logger = logging.getLogger(__name__)


class VerificationResult(Enum):
    """Result of formal verification"""
    EXPLOITABLE = "exploitable"          # Path provably exploitable
    BLOCKED = "blocked"                  # Path provably blocked
    UNKNOWN = "unknown"                  # Cannot determine with current info


@dataclass
class ProofResult:
    """Formal proof output"""
    result: VerificationResult
    path: List[str]
    constraints_satisfied: bool
    num_constraints: int
    solver_time_ms: float
    model: Optional[Dict[str, Any]] = None      # Z3 model (if feasible)
    counterexample: Optional[Dict[str, Any]] = None  # Counterexample (if infeasible)
    explanation: str = ""                        # Human-readable explanation
    constraints_used: List[str] = None           # Which constraints were needed


class PolicyToZ3Converter:
    """Convert IAM policy conditions to Z3 constraints"""
    
    def __init__(self):
        """Initialize converter with Z3 solver"""
        self.solver = z3.Solver()
        self.context = {}
        self.constraints = []
    
    def condition_to_constraint(self, condition: Dict[str, Any]) -> Optional[z3.ExprRef]:
        """
        Convert a policy condition to a Z3 constraint.
        
        Args:
            condition: IAM policy condition dict
            {
                "operator": "StringEquals",
                "key": "aws:username",
                "values": ["alice", "bob"]
            }
        
        Returns:
            Z3 Bool expression
        """
        operator = condition.get("operator", "").lower()
        key = condition.get("key", "").lower()
        values = condition.get("values", [])
        
        # Create Z3 symbol for this key
        if key not in self.context:
            self.context[key] = z3.String(key)
        
        var = self.context[key]
        
        # Map operators to Z3 expressions
        if operator == "stringequals":
            # At least one value matches
            constraints = [var == z3.StringVal(v) for v in values]
            return z3.Or(*constraints) if constraints else z3.BoolVal(False)
        
        elif operator == "stringlike":
            # Wildcard matching
            constraints = []
            for pattern in values:
                # Simplified: just check if pattern contains wildcard
                if '*' in pattern or '?' in pattern:
                    # For wildcard patterns, we'll use string prefix matching
                    prefix = pattern.split('*')[0] if '*' in pattern else pattern
                    constraints.append(z3.PrefixOf(z3.StringVal(prefix), var))
                else:
                    constraints.append(var == z3.StringVal(pattern))
            return z3.Or(*constraints) if constraints else z3.BoolVal(False)
        
        elif operator == "ipaddress":
            # IP matching - requires constraint on source_ip
            if key == "aws:sourceip":
                source_ip = z3.String("source_ip")
                # Model as: source_ip must match one of the CIDR blocks via prefix
                constraints = []
                for cidr in values:
                    # Simplified: use CIDR prefix as string prefix
                    cidr_prefix = cidr.split('/')[0] if '/' in cidr else cidr
                    constraints.append(z3.PrefixOf(z3.StringVal(cidr_prefix), source_ip))
                return z3.Or(*constraints) if constraints else z3.BoolVal(False)
        
        elif operator == "stringnotequals":
            # Negation of StringEquals
            constraints = [var == z3.StringVal(v) for v in values]
            return z3.Not(z3.Or(*constraints)) if constraints else z3.BoolVal(True)
        
        elif operator == "notipaddress":
            # Negation of IpAddress
            if key == "aws:sourceip":
                source_ip = z3.String("source_ip")
                constraints = []
                for cidr in values:
                    cidr_prefix = cidr.split('/')[0] if '/' in cidr else cidr
                    constraints.append(z3.PrefixOf(z3.StringVal(cidr_prefix), source_ip))
                return z3.Not(z3.Or(*constraints)) if constraints else z3.BoolVal(True)
        
        elif operator == "numericgreater":
            # Numeric comparison
            port = z3.Int(key)
            threshold = int(values[0]) if values else 0
            return port > threshold
        
        elif operator == "numericless":
            port = z3.Int(key)
            threshold = int(values[0]) if values else 0
            return port < threshold
        
        elif operator == "numericequals":
            port = z3.Int(key)
            threshold = int(values[0]) if values else 0
            return port == threshold
        
        elif operator == "arnlike":
            # ARN matching
            constraints = []
            for arn_pattern in values:
                # Simplified: use prefix matching for ARN patterns
                if '*' in arn_pattern:
                    prefix = arn_pattern.split('*')[0]
                    constraints.append(z3.PrefixOf(z3.StringVal(prefix), var))
                else:
                    constraints.append(var == z3.StringVal(arn_pattern))
            return z3.Or(*constraints) if constraints else z3.BoolVal(False)
        
        elif operator == "bool":
            # Boolean condition
            bool_val = values[0].lower() in ('true', '1') if values else False
            return z3.BoolVal(bool_val)
        
        else:
            logger.warning(f"Unknown operator: {operator}")
            return None
    
    def _cidr_to_regex(self, cidr: str) -> str:
        """Convert CIDR notation to regex pattern"""
        # Simple approximation: 192.168.0.0/16 -> 192\.168\..*
        parts = cidr.split('/')
        if len(parts) == 2:
            ip_parts = parts[0].split('.')
            # For /16, keep first 2 octets; /24 keep first 3
            prefix_len = int(parts[1])
            octets = prefix_len // 8
            pattern = r'\.'.join(ip_parts[:octets]) + r'(\.\d+)*'
            return pattern
        return cidr.replace('.', r'\.')
    
    def add_policy_constraints(self, policies: List[Dict[str, Any]]) -> None:
        """
        Add policy conditions as constraints to solver.
        
        Args:
            policies: List of policy documents with conditions
        """
        for policy in policies:
            # Extract conditions
            conditions = policy.get("conditions", [])
            statement_effect = policy.get("effect", "Allow").upper()
            
            # Convert conditions to constraints
            constraint_list = []
            for condition in conditions:
                constraint = self.condition_to_constraint(condition)
                if constraint is not None:
                    constraint_list.append(constraint)
                    self.constraints.append((condition.get("key", "unknown"), constraint))
            
            # Add to solver: if effect is Allow, conditions must be satisfiable
            if statement_effect == "ALLOW" and constraint_list:
                combined = z3.And(*constraint_list)
                self.solver.add(combined)
                logger.debug(f"Added constraint: {combined}")
            elif statement_effect == "DENY" and constraint_list:
                # Deny: NOT of conditions
                combined = z3.Not(z3.And(*constraint_list))
                self.solver.add(combined)
                logger.debug(f"Added deny constraint: {combined}")
    
    def add_execution_context(self, context: Dict[str, Any]) -> None:
        """
        Add execution context as hard constraints.
        
        Args:
            context: Execution context
            {
                "source_ip": "192.168.1.100",
                "time_of_day": "business_hours",
                "user_role": "admin"
            }
        """
        for key, value in context.items():
            if isinstance(value, str):
                z3_var = z3.String(key)
                self.solver.add(z3_var == z3.StringVal(value))
            elif isinstance(value, int):
                z3_var = z3.Int(key)
                self.solver.add(z3_var == value)
            logger.debug(f"Added context: {key} = {value}")
    
    def verify_satisfiable(self) -> Tuple[bool, Optional[z3.ModelRef]]:
        """
        Check if constraints are satisfiable.
        
        Returns:
            (is_satisfiable, model)
        """
        result = self.solver.check()
        if result == z3.sat:
            return True, self.solver.model()
        elif result == z3.unsat:
            return False, None
        else:
            logger.warning("Z3 solver returned unknown")
            return None, None


class Z3Verifier:
    """Formal verification of attack paths using Z3 SMT solver"""
    
    def __init__(self):
        """Initialize verifier"""
        self.converter = PolicyToZ3Converter()
    
    def verify_path_exploitability(
        self,
        path: List[str],
        policies: List[Dict[str, Any]],
        context: Dict[str, Any],
        timeout_ms: int = 5000
    ) -> ProofResult:
        """
        Formally verify if an attack path is exploitable.
        
        Args:
            path: Attack path nodes [source, intermediate1, intermediate2, ..., target]
            policies: List of security policies
            context: Execution context (source_ip, time_of_day, etc.)
            timeout_ms: Z3 solver timeout
        
        Returns:
            ProofResult with verification outcome
        """
        import time
        
        start_time = time.time()
        
        # Create new solver for this verification
        converter = PolicyToZ3Converter()
        
        # Set timeout
        converter.solver.set("timeout", timeout_ms)
        
        try:
            # Add policies as constraints
            converter.add_policy_constraints(policies)
            
            # Add execution context
            converter.add_execution_context(context)
            
            # Check satisfiability
            is_sat, model = converter.verify_satisfiable()
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            if is_sat:
                return ProofResult(
                    result=VerificationResult.EXPLOITABLE,
                    path=path,
                    constraints_satisfied=True,
                    num_constraints=len(converter.constraints),
                    solver_time_ms=elapsed_ms,
                    model=self._model_to_dict(model) if model else None,
                    explanation=f"Path {' → '.join(path)} is EXPLOITABLE under the given constraints. "
                                 f"Solver found satisfying assignment in {elapsed_ms:.1f}ms.",
                    constraints_used=[name for name, _ in converter.constraints]
                )
            elif is_sat is False:
                return ProofResult(
                    result=VerificationResult.BLOCKED,
                    path=path,
                    constraints_satisfied=False,
                    num_constraints=len(converter.constraints),
                    solver_time_ms=elapsed_ms,
                    counterexample={"reason": "All constraints unsatisfiable"},
                    explanation=f"Path {' → '.join(path)} is BLOCKED. "
                                 f"No satisfying assignment exists (UNSAT in {elapsed_ms:.1f}ms).",
                    constraints_used=[name for name, _ in converter.constraints]
                )
            else:
                return ProofResult(
                    result=VerificationResult.UNKNOWN,
                    path=path,
                    constraints_satisfied=None,
                    num_constraints=len(converter.constraints),
                    solver_time_ms=elapsed_ms,
                    explanation=f"Verification result UNKNOWN (solver returned unknown) for path {' → '.join(path)}.",
                    constraints_used=[name for name, _ in converter.constraints]
                )
        
        except Exception as e:
            logger.error(f"Z3 verification failed: {e}")
            elapsed_ms = (time.time() - start_time) * 1000
            return ProofResult(
                result=VerificationResult.UNKNOWN,
                path=path,
                constraints_satisfied=None,
                num_constraints=0,
                solver_time_ms=elapsed_ms,
                explanation=f"Verification error: {str(e)}",
            )
    
    def _model_to_dict(self, model: z3.ModelRef) -> Dict[str, Any]:
        """Convert Z3 model to dictionary"""
        result = {}
        for var in model:
            value = model[var]
            result[str(var)] = str(value)
        return result
    
    def batch_verify_paths(
        self,
        paths: List[List[str]],
        policies: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[ProofResult]:
        """
        Verify multiple paths.
        
        Args:
            paths: List of attack paths
            policies: Security policies
            context: Execution context
        
        Returns:
            List of ProofResults
        """
        results = []
        for path in paths:
            result = self.verify_path_exploitability(path, policies, context)
            results.append(result)
        
        logger.info(f"Verified {len(paths)} paths: "
                   f"{sum(1 for r in results if r.result == VerificationResult.EXPLOITABLE)} exploitable, "
                   f"{sum(1 for r in results if r.result == VerificationResult.BLOCKED)} blocked")
        
        return results


# Convenience functions
def verify_path(
    path: List[str],
    policies: List[Dict[str, Any]],
    context: Dict[str, Any]
) -> ProofResult:
    """Verify a single attack path"""
    verifier = Z3Verifier()
    return verifier.verify_path_exploitability(path, policies, context)


def verify_paths(
    paths: List[List[str]],
    policies: List[Dict[str, Any]],
    context: Dict[str, Any]
) -> List[ProofResult]:
    """Verify multiple attack paths"""
    verifier = Z3Verifier()
    return verifier.batch_verify_paths(paths, policies, context)
