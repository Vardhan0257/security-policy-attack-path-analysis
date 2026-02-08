"""Threat Scorer - Combines CVSS metrics, Z3 verification, and attack path characteristics to produce threat scores."""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level classifications."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @property
    def score_range(self) -> Tuple[float, float]:
        """Get score range for this threat level."""
        ranges = {
            ThreatLevel.CRITICAL: (9.0, 10.0),
            ThreatLevel.HIGH: (7.0, 8.9),
            ThreatLevel.MEDIUM: (4.0, 6.9),
            ThreatLevel.LOW: (0.1, 3.9),
            ThreatLevel.INFORMATIONAL: (0.0, 0.0),
        }
        return ranges[self]


@dataclass
class ThreatScoreComponent:
    """Individual component of threat score."""
    name: str
    value: float
    weight: float
    description: str

    @property
    def weighted_value(self) -> float:
        """Get weighted component value."""
        return self.value * self.weight


@dataclass
class PathThreatScore:
    """Complete threat score for an attack path."""
    path_id: str
    path: List[str]
    overall_score: float
    threat_level: ThreatLevel
    components: List[ThreatScoreComponent] = field(default_factory=list)
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    lineage_score: float = 0.0  # Based on path length/complexity
    confidence_score: float = 0.0  # Based on Z3 verification
    cve_count: int = 0
    max_cve_score: Optional[float] = None
    recommendations: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"[{self.threat_level.value}] Path: {' → '.join(self.path)} Score: {self.overall_score:.1f}/10"

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "path_id": self.path_id,
            "path": self.path,
            "overall_score": round(self.overall_score, 1),
            "threat_level": self.threat_level.value,
            "exploitability_score": round(self.exploitability_score, 2),
            "impact_score": round(self.impact_score, 2),
            "lineage_score": round(self.lineage_score, 2),
            "confidence_score": round(self.confidence_score, 2),
            "cve_count": self.cve_count,
            "max_cve_score": round(self.max_cve_score, 1) if self.max_cve_score else None,
            "components": [
                {
                    "name": c.name,
                    "value": round(c.value, 2),
                    "weight": c.weight,
                    "weighted_value": round(c.weighted_value, 2),
                    "description": c.description,
                }
                for c in self.components
            ],
            "recommendations": self.recommendations,
        }


class PathThreatScorer:
    """Threat Scorer - Produces risk scores for attack paths."""

    # Weighting factors for score calculation
    WEIGHTS = {
        "exploitability": 0.35,
        "impact": 0.35,
        "lineage": 0.20,
        "confidence": 0.10,
    }

    def __init__(self):
        """Initialize threat scorer."""
        pass

    def score_path(
        self,
        path: List[str],
        is_exploitable: bool,
        cvss_base_score: Optional[float] = None,
        z3_confidence: float = 1.0,
        cve_count: int = 0,
        max_cve_score: Optional[float] = None,
        has_authentication_bypass: bool = False,
        has_privilege_escalation: bool = False,
    ) -> PathThreatScore:
        """
        Score an attack path considering multiple factors.

        Args:
            path: Attack path nodes
            is_exploitable: Whether path is exploitable (Z3 verification)
            cvss_base_score: CVSS base score if available
            z3_confidence: Z3 verification confidence (0-1)
            cve_count: Number of associated CVEs
            max_cve_score: Maximum CVSS score from associated CVEs
            has_authentication_bypass: Whether path involves auth bypass
            has_privilege_escalation: Whether path involves privesc

        Returns:
            PathThreatScore with detailed threat assessment
        """
        path_id = self._path_to_id(path)

        # Calculate component scores
        exploitability = self._calculate_exploitability(
            is_exploitable,
            len(path),
            has_authentication_bypass,
            has_privilege_escalation,
        )

        impact = self._calculate_impact(
            cvss_base_score or 0.0,
            max_cve_score or 0.0,
            cve_count,
        )

        lineage = self._calculate_lineage_score(path)
        confidence = self._calculate_confidence(z3_confidence, is_exploitable)

        # Calculate overall score
        overall_score = (
            exploitability * self.WEIGHTS["exploitability"] +
            impact * self.WEIGHTS["impact"] +
            lineage * self.WEIGHTS["lineage"] +
            confidence * self.WEIGHTS["confidence"]
        )

        # Ensure score is between 0 and 10
        overall_score = min(10.0, max(0.0, overall_score))

        # Determine threat level
        threat_level = self._score_to_threat_level(overall_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            path, is_exploitable, cvss_base_score, cve_count
        )

        # Build components list
        components = [
            ThreatScoreComponent(
                name="Exploitability",
                value=exploitability,
                weight=self.WEIGHTS["exploitability"],
                description="Ease of exploitation based on path structure",
            ),
            ThreatScoreComponent(
                name="Impact",
                value=impact,
                weight=self.WEIGHTS["impact"],
                description="Severity of impact if path is exploited",
            ),
            ThreatScoreComponent(
                name="Lineage",
                value=lineage,
                weight=self.WEIGHTS["lineage"],
                description="Attack path complexity and length",
            ),
            ThreatScoreComponent(
                name="Confidence",
                value=confidence,
                weight=self.WEIGHTS["confidence"],
                description="Confidence in Z3 verification result",
            ),
        ]

        return PathThreatScore(
            path_id=path_id,
            path=path,
            overall_score=overall_score,
            threat_level=threat_level,
            components=components,
            exploitability_score=exploitability,
            impact_score=impact,
            lineage_score=lineage,
            confidence_score=confidence,
            cve_count=cve_count,
            max_cve_score=max_cve_score,
            recommendations=recommendations,
        )

    def _calculate_exploitability(
        self,
        is_exploitable: bool,
        path_length: int,
        has_auth_bypass: bool,
        has_privesc: bool,
    ) -> float:
        """
        Calculate exploitability score (0-10).

        Factors:
        - Is path actually exploitable?
        - How many steps required?
        - Are there auth bypass/privesc opportunities?
        """
        if not is_exploitable:
            return 0.0

        # Base score for exploitable path
        score = 6.0

        # Reduce score based on path length (longer = more difficult)
        # Each additional hop -0.5, min 3.5
        score -= max(0.0, (path_length - 1) * 0.5)
        score = max(3.5, score)

        # Increase score for auth bypass
        if has_auth_bypass:
            score += 1.5

        # Increase score for privilege escalation
        if has_privesc:
            score += 1.0

        return min(10.0, score)

    def _calculate_impact(
        self,
        cvss_base_score: float,
        max_cve_score: float,
        cve_count: int,
    ) -> float:
        """
        Calculate impact score (0-10).

        Factors:
        - CVSS base score of potential vulnerability
        - Maximum CVSS from associated CVEs
        - Number of related vulnerabilities
        """
        # Use higher of CVSS or CVE score
        max_score = max(cvss_base_score, max_cve_score or 0.0)

        # If no CVE data, use conservative estimate
        if max_score == 0.0:
            max_score = 5.0  # Medium impact estimate

        # Bonus for multiple CVEs (increased attack surface)
        if cve_count > 0:
            # Cap at +1.0 bonus
            bonus = min(1.0, cve_count * 0.2)
            max_score = min(10.0, max_score + bonus)

        return max_score

    def _calculate_lineage_score(self, path: List[str]) -> float:
        """
        Calculate lineage score based on path complexity (0-10).

        - Short paths (2-3 hops): Higher score (9-10)
        - Medium paths (4-6 hops): Medium score (6-8)
        - Long paths (7+ hops): Lower score (3-6)
        """
        length = len(path)

        if length <= 3:
            return 9.5 - (length - 1) * 0.5  # 9.5, 9.0, 8.5
        elif length <= 6:
            return 7.0 - (length - 3) * 0.5  # 7.0, 6.5, 6.0
        else:
            return max(3.0, 6.0 - (length - 6) * 0.3)  # Decreases slowly

    def _calculate_confidence(self, z3_confidence: float, is_exploitable: bool) -> float:
        """
        Calculate confidence score (0-10) based on Z3 verification.

        - Z3 verification provides high confidence
        - Confidence = z3_confidence * 10 if exploitable, 0 if not
        """
        if not is_exploitable:
            return 0.0

        return min(10.0, z3_confidence * 10.0)

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Map score to threat level."""
        if score >= 9.0:
            return ThreatLevel.CRITICAL
        elif score >= 7.0:
            return ThreatLevel.HIGH
        elif score >= 4.0:
            return ThreatLevel.MEDIUM
        elif score > 0.0:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFORMATIONAL

    def _generate_recommendations(
        self,
        path: List[str],
        is_exploitable: bool,
        cvss_score: Optional[float],
        cve_count: int,
    ) -> List[str]:
        """Generate security recommendations based on threat assessment."""
        recommendations = []

        if not is_exploitable:
            recommendations.append("No immediate action required - path not exploitable.")
            return recommendations

        # Recommend segmentation/isolation
        if len(path) > 4:
            recommendations.append(
                f"Consider network segmentation: Break path by isolating {path[len(path)//2]}"
            )

        # Specific target recommendations
        target = path[-1] if path else "unknown"
        if target in ["database", "secrets", "admin"]:
            recommendations.append(
                f"Increase access controls on {target}: Implement MFA and least-privilege IAM"
            )

        # CVE-specific recommendations
        if cve_count > 0:
            recommendations.append(
                f"Review {cve_count} associated CVEs and apply patches"
            )
        elif cvss_score and cvss_score >= 7.0:
            recommendations.append(
                "High CVSS score detected - prioritize remediation"
            )

        # General hardening
        recommendations.append(
            "Implement detective controls (CloudTrail, VPC Flow Logs)"
        )

        return recommendations

    def _path_to_id(self, path: List[str]) -> str:
        """Convert path to unique ID."""
        return "|".join(path)

    def score_multiple_paths(
        self,
        paths: List[Dict],
    ) -> List[PathThreatScore]:
        """
        Score multiple paths efficiently.

        Args:
            paths: List of dicts with path data

        Returns:
            Sorted list of PathThreatScore (highest risk first)
        """
        scores = []

        for path_data in paths:
            score = self.score_path(
                path=path_data.get("path", []),
                is_exploitable=path_data.get("is_exploitable", False),
                cvss_base_score=path_data.get("cvss_base_score"),
                z3_confidence=path_data.get("z3_confidence", 1.0),
                cve_count=path_data.get("cve_count", 0),
                max_cve_score=path_data.get("max_cve_score"),
                has_authentication_bypass=path_data.get("has_authentication_bypass", False),
                has_privilege_escalation=path_data.get("has_privilege_escalation", False),
            )
            scores.append(score)

        # Sort by threat score (highest first)
        scores.sort(key=lambda x: x.overall_score, reverse=True)

        return scores
