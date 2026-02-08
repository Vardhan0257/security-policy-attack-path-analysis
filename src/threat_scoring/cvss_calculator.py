"""CVSS v3.1 Score Calculator - Maps security vulnerabilities to common weakness enumeration metrics."""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class CVSSScope(Enum):
    """CVSS Scope - whether vulnerability impact is limited to affected component."""
    UNCHANGED = "U"  # Impact limited to vulnerable component
    CHANGED = "C"    # Scope break - impact extends beyond vulnerable component


class CVSSComplexity(Enum):
    """Attack Complexity - conditions beyond attacker's control needed."""
    LOW = "L"         # Specialized access/conditions not required
    HIGH = "H"        # Special conditions needed (e.g., race condition, hypervisor)


class CVSSPrivileges(Enum):
    """Privileges Required - attacker must possess to exploit."""
    NONE = "N"        # No privileges required
    LOW = "L"         # Low-level privileges (e.g., unprivileged user)
    HIGH = "H"        # High-level privileges (e.g., admin/root)


class CVSSUserInteraction(Enum):
    """User Interaction - action by someone other than attacker."""
    NONE = "N"        # No user interaction required
    REQUIRED = "R"    # User interaction required (e.g., click link)


class CVSSImpactType(Enum):
    """Impact Type - effect on security property of affected component."""
    NONE = "N"        # No impact
    LOW = "L"         # Limited impact, no obvious loss
    HIGH = "H"        # Total information disclosure/total loss


@dataclass
class CVSSScore:
    """CVSS v3.1 Score with vector string."""
    base_score: float
    temporal_score: float
    severity: str
    vector_string: str
    details: dict

    @property
    def severity_color(self) -> str:
        """Get severity color for UI display."""
        score = self.base_score
        if score == 0.0:
            return "gray"
        elif score < 4.0:
            return "yellow"
        elif score < 7.0:
            return "orange"
        elif score < 9.0:
            return "red"
        else:
            return "darkred"

    def __str__(self) -> str:
        return f"CVSS:3.1/{self.vector_string} Base:{self.base_score:.1f} Temporal:{self.temporal_score:.1f} ({self.severity})"


class CVSSCalculator:
    """CVSS v3.1 Base Score Calculator."""

    # Metric weights for scoring
    METRIC_WEIGHTS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 1.0, "C": 1.0},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }

    def calculate_base_score(
        self,
        attack_vector: str = "N",  # Network
        attack_complexity: str = "L",  # Low
        privileges_required: str = "N",  # None
        user_interaction: str = "N",  # None
        scope: str = "U",  # Unchanged
        confidentiality: str = "N",  # None
        integrity: str = "N",  # None
        availability: str = "N",  # None
    ) -> CVSSScore:
        """
        Calculate CVSS v3.1 base score.

        Args:
            attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
            attack_complexity: L (Low), H (High)
            privileges_required: N (None), L (Low), H (High)
            user_interaction: N (None), R (Required)
            scope: U (Unchanged), C (Changed)
            confidentiality: N (None), L (Low), H (High)
            integrity: N (None), L (Low), H (High)
            availability: N (None), L (Low), H (High)

        Returns:
            CVSSScore with base_score, temporal_score, severity, and vector
        """
        # Validate inputs
        self._validate_inputs(
            attack_vector, attack_complexity, privileges_required, user_interaction,
            scope, confidentiality, integrity, availability
        )

        # Calculate impact metrics
        impact_confidentiality = self.METRIC_WEIGHTS["C"][confidentiality]
        impact_integrity = self.METRIC_WEIGHTS["I"][integrity]
        impact_availability = self.METRIC_WEIGHTS["A"][availability]

        # Calculate impact (formula from CVSS v3.1 spec)
        impact_score = 1 - ((1 - impact_confidentiality) * (1 - impact_integrity) * (1 - impact_availability))

        # Scope impact multiplier
        if scope == "C":
            impact_score = 7.52 * (impact_score - 0.029) - 3.25 * ((impact_score - 0.02) ** 15)
        else:
            impact_score = 6.42 * impact_score

        # If no impact, base score is 0
        if impact_score <= 0:
            vector = self._build_vector(
                attack_vector, attack_complexity, privileges_required, user_interaction,
                scope, confidentiality, integrity, availability
            )
            return CVSSScore(
                base_score=0.0,
                temporal_score=0.0,
                severity="None",
                vector_string=vector,
                details={"impact": 0.0, "exploitability": 0.0}
            )

        # Calculate exploitability
        av_weight = self.METRIC_WEIGHTS["AV"].get(attack_vector, 0.85)
        ac_weight = self.METRIC_WEIGHTS["AC"].get(attack_complexity, 0.77)
        pr_weight = self._get_pr_weight(privileges_required, scope)
        ui_weight = self.METRIC_WEIGHTS["UI"].get(user_interaction, 0.85)

        exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight

        # Calculate base score
        base_score = min(10.0, (impact_score + exploitability) * 0.9 if exploitability > 0 else impact_score)

        # Round to 1 decimal place
        base_score = round(base_score, 1)

        # Map to severity
        severity = self._score_to_severity(base_score)

        # Calculate temporal score (simplified: assume no temporal factors)
        temporal_score = base_score

        # Build vector string
        vector = self._build_vector(
            attack_vector, attack_complexity, privileges_required, user_interaction,
            scope, confidentiality, integrity, availability
        )

        return CVSSScore(
            base_score=base_score,
            temporal_score=temporal_score,
            severity=severity,
            vector_string=vector,
            details={
                "impact": impact_score,
                "exploitability": exploitability,
                "av": av_weight,
                "ac": ac_weight,
                "pr": pr_weight,
                "ui": ui_weight,
            }
        )

    def calculate_from_vector(self, vector_string: str) -> CVSSScore:
        """
        Parse CVSS vector string and calculate score.

        Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        """
        try:
            # Remove CVSS:3.1 prefix if present
            if vector_string.startswith("CVSS:3.1/"):
                vector_string = vector_string[9:]

            # Parse components
            metrics = {}
            for component in vector_string.split("/"):
                if ":" in component:
                    key, value = component.split(":")
                    metrics[key] = value

            # Map vector abbreviations to parameter names
            return self.calculate_base_score(
                attack_vector=metrics.get("AV", "N"),
                attack_complexity=metrics.get("AC", "L"),
                privileges_required=metrics.get("PR", "N"),
                user_interaction=metrics.get("UI", "N"),
                scope=metrics.get("S", "U"),
                confidentiality=metrics.get("C", "N"),
                integrity=metrics.get("I", "N"),
                availability=metrics.get("A", "N"),
            )
        except Exception as e:
            logger.error(f"Error parsing CVSS vector: {vector_string}: {e}")
            raise ValueError(f"Invalid CVSS vector: {vector_string}")

    def _get_pr_weight(self, pr: str, scope: str) -> float:
        """Get PR weight based on scope."""
        if pr == "N":
            return 0.85
        elif pr == "L":
            return 0.68 if scope == "U" else 0.62
        elif pr == "H":
            return 0.50 if scope == "U" else 0.27
        else:
            return 0.85

    def _build_vector(
        self, av, ac, pr, ui, scope, c, i, a
    ) -> str:
        """Build CVSS vector string."""
        return f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"

    def _score_to_severity(self, score: float) -> str:
        """Map score to severity rating."""
        if score == 0.0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"

    def _validate_inputs(self, av, ac, pr, ui, scope, c, i, a) -> None:
        """Validate CVSS metric inputs."""
        valid_av = {"N", "A", "L", "P"}
        valid_ac = {"L", "H"}
        valid_pr = {"N", "L", "H"}
        valid_ui = {"N", "R"}
        valid_scope = {"U", "C"}
        valid_impact = {"N", "L", "H"}

        if av not in valid_av:
            raise ValueError(f"Invalid AV: {av}")
        if ac not in valid_ac:
            raise ValueError(f"Invalid AC: {ac}")
        if pr not in valid_pr:
            raise ValueError(f"Invalid PR: {pr}")
        if ui not in valid_ui:
            raise ValueError(f"Invalid UI: {ui}")
        if scope not in valid_scope:
            raise ValueError(f"Invalid Scope: {scope}")
        if c not in valid_impact:
            raise ValueError(f"Invalid C: {c}")
        if i not in valid_impact:
            raise ValueError(f"Invalid I: {i}")
        if a not in valid_impact:
            raise ValueError(f"Invalid A: {a}")


class ThreatAssessment:
    """Assess threat level of attack path based on CVSS metrics."""

    def __init__(self):
        self.calculator = CVSSCalculator()

    def assess_attack_path(
        self,
        path: list,
        is_exploitable: bool,
        requires_authentication: bool = False,
        requires_user_interaction: bool = False,
        network_proximity_required: bool = True,
    ) -> Tuple[float, str, dict]:
        """
        Assess threat level of attack path.

        Args:
            path: Attack path nodes
            is_exploitable: Whether path is exploitable (from Z3 verification)
            requires_authentication: Whether authentication required
            requires_user_interaction: Whether user action needed
            network_proximity_required: Whether attacker must be on same network

        Returns:
            Tuple of (threat_score, severity, details)
        """
        if not is_exploitable:
            return 0.0, "None", {"reason": "Path not exploitable"}

        # Determine CVSS metrics based on attack characteristics
        attack_vector = "L" if network_proximity_required else "N"
        user_interaction = "R" if requires_user_interaction else "N"
        privileges_required = "L" if requires_authentication else "N"

        # Assume worse-case impact (all confidentiality, integrity, availability)
        cvss_score = self.calculator.calculate_base_score(
            attack_vector=attack_vector,
            attack_complexity="L",
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope="C",  # Changed scope = higher impact
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        return cvss_score.base_score, cvss_score.severity, {
            "cvss_vector": cvss_score.vector_string,
            "base_score": cvss_score.base_score,
            "temporal_score": cvss_score.temporal_score,
            "path_length": len(path),
            "access_requirements": {
                "authentication_required": requires_authentication,
                "user_interaction_required": requires_user_interaction,
                "network_proximity_required": network_proximity_required,
            }
        }
